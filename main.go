package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/term"
)

var version = "dev" // overridden via -ldflags "-X main.version=..."

// program implements the service lifecycle (Start/Stop) so the same code runs interactively, under systemd and as a Windows service.
type program struct {
	boot     *Bootstrap
	log      *slog.Logger
	closeLog func()
	store    *Store
	srv      *http.Server
	cancel   context.CancelFunc
	engDone  chan struct{}
	srvDone  chan struct{}
	addr     string

	lmu      sync.Mutex // guards srv, srvDone and addr while the listen address is being changed
	keeper   *certKeeper
	web      *Server
	stopOnce sync.Once
	lock     *DataLock // held from start to stop: one agent per data folder
}

// Start opens the key and the encrypted database, starts the scheduler and the web server, and returns once they are running.
func (p *program) Start(service.Service) error {
	log, closeLog, err := SetupLogger(p.boot.Logging)
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	p.log, p.closeLog = log, closeLog
	fail := func(err error) error {
		log.Error("startup failed", "err", err)
		p.lock.Release()
		closeLog()
		return err
	}

	wait := time.Duration(0)
	if p.boot.AfterUpdate {
		wait = time.Minute // the version being replaced is still shutting down
	}
	if p.lock, err = LockDataDirWait(p.boot.DataDir, wait); err != nil {
		return fail(err)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		printDataLocation(promptOut, p.boot)
	}
	if err := ensureKeyFile(p.boot, log); err != nil {
		return fail(err)
	}
	vault, err := OpenVault(p.boot.KeyPath())
	if err != nil {
		return fail(fmt.Errorf("key file %s: %w", p.boot.KeyPath(), err))
	}
	// The database is encrypted as a whole (AES-256-XTS); see tde.go.
	store, err := OpenEncryptedStore(p.boot.DBPath(), vault.DBKey(), log)
	if err != nil {
		return fail(fmt.Errorf("database %s: %w", p.boot.DBPath(), err))
	}
	p.store = store
	if err := store.SetVault(vault); err != nil {
		_ = store.Close()
		return fail(fmt.Errorf("securing stored credentials: %w", err))
	}
	log.Info("data location", "dir", p.boot.DataDir, "database", p.boot.DBPath())
	if p.boot.LegacyDataDir {
		log.Warn("the database and key are stored next to the program (older layout). Move them to the dedicated data folder with:  easm-agent -migrate-data  (stop the agent first)")
	}
	if p.boot.DataDirWarning != "" {
		log.Warn("could not restrict access to the data folder; set its permissions by hand", "err", p.boot.DataDirWarning)
	}

	// An address chosen in the web interface is used unless the command line or config file fixed one.
	if !p.boot.ListenExplicit {
		if v, ok, _ := store.getMeta(metaListen); ok && v != "" {
			if _, _, perr := net.SplitHostPort(v); perr == nil {
				p.boot.Listen = v
			}
		}
	}

	eng := NewEngine(store, vault, log)
	eng.dataDir = p.boot.DataDir
	web, err := NewServer(store, eng, log, p.boot)
	if err != nil {
		_ = store.Close()
		return fail(err)
	}
	if p.boot.AutoTLS() {
		// No certificate was supplied: make (or reuse) a self-signed one so traffic is always encrypted.
		if p.keeper, err = newCertKeeper(p.boot.DataDir, p.boot.Listen, p.boot.AllowedHosts, log); err != nil {
			_ = store.Close()
			return fail(fmt.Errorf("TLS certificate: %w", err))
		}
	}
	if p.keeper != nil {
		p.keeper.attachVault(vault) // lets an administrator-uploaded certificate be loaded and its key sealed
		web.certs = p.keeper
	}
	ln, err := net.Listen("tcp", p.boot.Listen) // fail fast if the port is taken
	if err != nil {
		_ = store.Close()
		return fail(fmt.Errorf("cannot listen on %s: %w", p.boot.Listen, err))
	}
	p.addr = ln.Addr().String()
	p.web = web
	web.listen = p

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.engDone = make(chan struct{})
	p.srv, p.srvDone = p.startServing(ln)

	scheme := p.scheme()
	host, _, _ := net.SplitHostPort(p.addr)
	if ip := net.ParseIP(host); scheme == "http" && ip != nil && !ip.IsLoopback() && !p.boot.SecureCookies {
		log.Warn("serving plain HTTP on a non-loopback address: passwords and session cookies cross the network unencrypted. " +
			"Remove plain_http, set tls_cert/tls_key, or put the agent behind a TLS reverse proxy (and set secure_cookies: true)")
	}
	log.Info("agent started", "version", version, "data_dir", p.boot.DataDir, "url", scheme+"://"+displayAddr(p.addr))

	go func() { defer close(p.engDone); eng.Run(ctx) }()
	if service.Interactive() {
		web.stop = p.stopInteractive
		if runtime.GOOS == "windows" { // a new console window can ask for the passphrase again
			web.restart = p.restartAfterUpdate
		}
		p.desktopStart(scheme + "://" + displayAddr(p.addr))
	}
	return nil
}

// desktopStart finishes an interactive start: it opens the web interface in the
// default browser and, when the program has a console window of its own (it was
// double-clicked on Windows), hides that window so the agent keeps running in the
// background. Stop it from System health → Stop agent, or run it as a service.
func (p *program) desktopStart(link string) {
	fmt.Printf("\nEASM Agent %s is running at %s\n", version, link)
	if !p.boot.NoBrowser {
		if err := openBrowser(link); err != nil {
			fmt.Printf("Open %s in your browser.\n", link)
			p.log.Info("browser not opened", "reason", err)
		}
	}
	if p.boot.KeepConsole || !ownsConsole() {
		fmt.Print("Press Ctrl-C to stop.\n\n")
		return
	}
	fmt.Print("This window will now hide; the agent keeps running in the background.\n" +
		"To stop it, sign in as an administrator and use System health → Stop agent.\n\n")
	go func() {
		time.Sleep(3 * time.Second) // long enough to read the message
		if hideConsole() {
			p.log.Info("console hidden; the agent runs in the background")
		}
	}()
}

// stopInteractive shuts the agent down from the web interface (interactive runs
// only, where no service manager or visible console can stop it). It returns at
// once so the confirmation page is delivered, then stops and exits.
func (p *program) stopInteractive() {
	p.stopOnce.Do(func() {
		go func() {
			time.Sleep(time.Second)
			_ = p.Stop(nil)
			os.Exit(0)
		}()
	})
}

// scheme is "https" when the interface is served over TLS, otherwise "http".
func (p *program) scheme() string {
	if p.boot.UsesTLS() {
		return "https"
	}
	return "http"
}

// startServing serves the web interface on ln in the background and returns the
// server and a channel that closes when it has stopped.
func (p *program) startServing(ln net.Listener) (*http.Server, chan struct{}) {
	srv := &http.Server{
		Handler:           p.web.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute, // test-email actions can take a while
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if p.keeper != nil {
		srv.TLSConfig = p.keeper.tlsConfig()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var err error
		switch {
		case p.keeper != nil:
			err = srv.ServeTLS(ln, "", "") // certificate comes from TLSConfig.GetCertificate
		case p.boot.TLSCert != "":
			err = srv.ServeTLS(ln, p.boot.TLSCert, p.boot.TLSKey)
		default:
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.log.Error("web server stopped unexpectedly", "err", err)
		}
	}()
	return srv, done
}

// Address implements ListenControl: the address the web server listens on now.
func (p *program) Address() string {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	return p.addr
}

// Locked implements ListenControl: true when the command line or config file fixed the address.
func (p *program) Locked() bool { return p.boot.ListenExplicit }

// Change implements ListenControl. It binds the new address first, so a failure
// leaves the running server untouched, then starts serving there, remembers the
// address and retires the old server after a short delay so the page that asked
// for the change can still be delivered.
func (p *program) Change(addr string) (string, error) {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	if p.keeper != nil {
		if err := p.keeper.setListen(addr, p.boot.AllowedHosts); err != nil {
			_ = ln.Close()
			return "", err
		}
	}
	if err := p.store.setMeta(metaListen, addr); err != nil {
		_ = ln.Close()
		return "", err
	}
	p.boot.Listen = addr
	p.web.setListen(addr)
	old, oldDone := p.srv, p.srvDone
	p.srv, p.srvDone = p.startServing(ln)
	p.addr = ln.Addr().String()
	go func() {
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = old.Shutdown(ctx)
		<-oldDone
	}()
	p.log.Info("web interface moved", "address", p.addr)
	return p.scheme() + "://" + displayAddr(p.addr), nil
}

// displayAddr turns a listen address into a URL a person can open.
func displayAddr(a string) string {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// Stop shuts the web server and scheduler down gracefully and closes the database.
func (p *program) Stop(service.Service) error {
	p.log.Info("agent stopping")
	p.cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	p.lmu.Lock()
	srv, srvDone := p.srv, p.srvDone
	p.lmu.Unlock()
	_ = srv.Shutdown(sctx)
	<-srvDone
	select {
	case <-p.engDone:
	case <-time.After(30 * time.Second):
		p.log.Warn("scheduler did not stop within 30s")
	}
	_ = p.store.Close()
	p.lock.Release()
	p.closeLog()
	return nil
}

// printDataLocation tells the person at the start-up prompt which files it unlocks.
func printDataLocation(w io.Writer, boot *Bootstrap) {
	_, _ = fmt.Fprintf(w, "EASM Agent %s\n  Data folder: %s\n  Database:    %s\n  Key file:    %s\n\n",
		version, boot.DataDir, boot.DBPath(), boot.KeyPath())
}

// fatalPause keeps a console window the program opened itself (started from
// Explorer) on screen long enough to read why it is closing.
const fatalPause = 5 * time.Second

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", err)
	if ownsConsole() {
		_, _ = fmt.Fprintf(os.Stderr, "This window closes in %d seconds.\n", int(fatalPause/time.Second))
		time.Sleep(fatalPause)
	}
	os.Exit(1)
}

// stdinLines is shared by every prompt: a reader per prompt would buffer the
// lines meant for the next one (e.g. "passphrase\nrepeat\n" piped in).
var stdinLines = sync.OnceValue(func() *bufio.Reader { return bufio.NewReader(os.Stdin) })

// readPassword reads a secret from the terminal without echo (or a line from a pipe).
func readPassword(prompt string) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return readLine(stdinLines())
}

// readLine returns the next line without its line ending; a last line with no
// newline still counts. Windows PowerShell 5.1 starts piped input with a UTF-8
// byte-order mark, which would otherwise become part of the first passphrase.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err == io.EOF && line != "" {
		err = nil
	}
	return strings.TrimPrefix(strings.TrimRight(line, "\r\n"), "\ufeff"), err
}

// keyProtection adds (protect) or removes the passphrase on easm.key.
func keyProtection(boot *Bootstrap, protect bool) error {
	if !protect {
		if err := UnprotectKeyFile(boot.KeyPath()); err != nil {
			return err
		}
		fmt.Println("easm.key is stored without a passphrase again.")
		return nil
	}
	pass, err := readPassword("New key-file passphrase: ")
	if err != nil || len(pass) < 12 {
		return errors.New("passphrase must be at least 12 characters")
	}
	if again, err := readPassword("Repeat passphrase: "); err != nil || again != pass {
		return errors.New("passphrases do not match")
	}
	if err := ProtectKeyFile(boot.KeyPath(), pass); err != nil {
		return err
	}
	fmt.Println("easm.key is now protected. Start the agent with EASM_KEY_PASSPHRASE set (services) or from a terminal (you will be prompted).")
	return nil
}

// resetPassword sets a new password for an existing user (offline recovery path).
func resetPassword(boot *Bootstrap, username string) error {
	lock, err := LockDataDir(boot.DataDir)
	if err != nil {
		return err
	}
	defer lock.Release()
	vault, err := OpenVault(boot.KeyPath())
	if err != nil {
		return err
	}
	store, err := OpenEncryptedStore(boot.DBPath(), vault.DBKey(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if err := store.SetVault(vault); err != nil {
		return err
	}
	u, err := store.GetUserByName(username)
	if err != nil {
		return fmt.Errorf("no user named %q", username)
	}
	pw, err := readPassword("New password for " + u.Username + ": ")
	if err != nil {
		return err
	}
	if err := validatePassword(pw); err != nil {
		return err
	}
	if pw2, err := readPassword("Repeat password: "); err != nil || pw2 != pw {
		return errors.New("passwords do not match")
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if err := store.SetPassword(u.ID, hash); err != nil {
		return err
	}
	fmt.Println("password updated for", u.Username, "(existing sign-ins end when the agent restarts)")
	return nil
}

// main parses command-line flags and runs the agent or one of its maintenance commands.
func main() {
	var (
		cfgPath   = flag.String("config", "", "optional bootstrap config file (listen address, data directory, TLS, logging)")
		listen    = flag.String("listen", "", "address for the web interface (default 127.0.0.1:8080)")
		dataDir   = flag.String("data-dir", "", "where to keep the database, key and log (default: %LocalAppData%\\EASM Agent on Windows, ~/.local/share/easm-agent or /var/lib/easm-agent on Linux)")
		svcAction = flag.String("service", "", "service control: install|uninstall|start|stop|restart|status")
		protectK  = flag.Bool("protect-key", false, "protect easm.key with a passphrase (asked for at start-up or read from EASM_KEY_PASSPHRASE), then exit")
		unprotect = flag.Bool("unprotect-key", false, "remove the passphrase protection from easm.key, then exit")
		resetPW   = flag.String("reset-password", "", "set a new password for the named user, then exit")
		noPass    = flag.Bool("no-passphrase", false, "first start only: create the encryption key without a passphrase (not recommended)")
		noBrowser = flag.Bool("no-browser", false, "do not open the web interface in the browser at start-up")
		keepCon   = flag.Bool("keep-console", false, "Windows: keep the console window visible instead of hiding it after start-up")
		plainHTTP = flag.Bool("plain-http", false, "serve unencrypted HTTP instead of HTTPS with an automatic self-signed certificate")
		restore   = flag.String("restore", "", "restore a backup .zip into the data folder (stop the agent first), then exit")
		force     = flag.Bool("force", false, "with -restore: replace an existing database (the old one is kept alongside)")
		migrate   = flag.Bool("migrate-data", false, "move an installation that lives next to the program into the default data folder, then exit")
		showVer   = flag.Bool("version", false, "print version and exit")
		updCheck  = flag.Bool("update-check", false, "say whether a newer release exists, then exit")
		updApply  = flag.Bool("update", false, "download, verify and install the newest release (stops and restarts the service if it runs as one), then exit")
		rollback  = flag.Bool("rollback", false, "go back to the version the last update replaced (stop the agent first), then exit")
		assumeYes = flag.Bool("yes", false, "with -update: do not ask for confirmation")
		afterUpd  = flag.Bool("after-update", false, "internal: started by an update; wait for the previous version to let go of the data folder")
	)
	flag.Parse()
	if *afterUpd {
		// Restarted by an update in a new console window: talk to that window so the
		// key passphrase can be asked for (see useOwnConsole).
		useOwnConsole()
		promptOut = os.Stderr
		_, _ = fmt.Fprintf(os.Stderr, "EASM Agent was updated to %s and is starting again.\n\n", version)
	}
	if *showVer {
		fmt.Println("easm-agent", version)
		return
	}

	boot, err := LoadBootstrap(*cfgPath)
	if err != nil {
		fatal(fmt.Errorf("config %s: %w", *cfgPath, err))
	}
	if *listen != "" {
		boot.Listen = *listen
	}
	if *dataDir != "" {
		boot.DataDir = *dataDir
	}
	if *listen != "" {
		boot.ListenExplicit = true
	}
	if *noPass {
		boot.NoPassphrase = true
	}
	if *plainHTTP {
		boot.PlainHTTP = true
	}
	if *noBrowser {
		boot.NoBrowser = true
	}
	if *keepCon {
		boot.KeepConsole = true
	}
	boot.AfterUpdate = *afterUpd
	if *updCheck {
		if err := updateCheckCommand(); err != nil {
			fatal(err)
		}
		return
	}
	if *migrate {
		if err := migrateCommand(); err != nil {
			fatal(err)
		}
		return
	}
	if err := boot.Finalize(); err != nil {
		fatal(err)
	}

	if *restore != "" {
		if err := restoreCommand(boot, *restore, *force); err != nil {
			fatal(err)
		}
		return
	}
	if *protectK || *unprotect {
		if err := keyProtection(boot, *protectK); err != nil {
			fatal(err)
		}
		return
	}
	if *resetPW != "" {
		if err := resetPassword(boot, *resetPW); err != nil {
			fatal(err)
		}
		return
	}

	args := []string{"-data-dir", boot.DataDir, "-listen", boot.Listen}
	if *cfgPath != "" {
		if abs, err := filepath.Abs(*cfgPath); err == nil {
			args = append(args, "-config", abs)
		}
	}
	prg := &program{boot: boot}
	svc, err := service.New(prg, &service.Config{
		Name: "easm-agent", DisplayName: "EASM Agent",
		Description: "Continuous external attack surface monitoring with a web interface",
		Arguments:   args,
	})
	if err != nil {
		fatal(err)
	}
	if *updApply || *rollback {
		if err := updateCommand(boot, svc, *rollback, *assumeYes); err != nil {
			fatal(err)
		}
		return
	}
	switch *svcAction {
	case "":
		if err := svc.Run(); err != nil { // interactive (Ctrl-C) and under systemd / Windows service manager
			fatal(err)
		}
	case "status":
		st, err := svc.Status()
		if err != nil {
			fatal(err)
		}
		names := map[service.Status]string{service.StatusRunning: "running", service.StatusStopped: "stopped", service.StatusUnknown: "unknown"}
		fmt.Println(names[st])
	default:
		if err := service.Control(svc, *svcAction); err != nil {
			fatal(fmt.Errorf("service %s: %w", *svcAction, err))
		}
		fmt.Println("service", *svcAction, "OK")
		if *svcAction == "install" {
			fmt.Printf("Start it with:  %s -service start\nThen open %s://%s in a browser.\n", os.Args[0], map[bool]string{true: "https", false: "http"}[boot.UsesTLS()], displayAddr(boot.Listen))
		}
	}
}

// migrateCommand implements -migrate-data.
func migrateCommand() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dst, _, err := platformDataDirNow()
	if err != nil {
		return err
	}
	moved, err := migrateLegacyData(filepath.Dir(exe), dst)
	if err != nil {
		return err
	}
	fmt.Printf("Moved %d file(s) to %s:\n  %s\nStart the agent normally; it will now use that folder.\n", len(moved), dst, strings.Join(moved, "\n  "))
	return nil
}

// restoreCommand implements -restore.
func restoreCommand(boot *Bootstrap, zipPath string, force bool) error {
	lock, err := LockDataDir(boot.DataDir)
	if err != nil {
		return err
	}
	defer lock.Release()
	done, err := RestoreBackup(zipPath, boot.DataDir, force, time.Now())
	for _, d := range done {
		fmt.Println(" -", d)
	}
	if err != nil {
		return err
	}
	fmt.Println("Verifying the restored database with the key file...")
	if verr := VerifyRestored(boot.DataDir, nil); verr != nil {
		fmt.Println("Restored, but it could not be verified yet:", verr)
		fmt.Println("If easm.key is missing or belongs to another installation, put the right key file in", boot.DataDir, "and start the agent.")
		return nil
	}
	fmt.Println("Restore complete and verified. Start the agent as usual.")
	return nil
}
