package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"
)

// updateCheckCommand implements -update-check.
func updateCheckCommand() error {
	u := NewUpdater()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := u.Latest(ctx)
	if errors.Is(err, ErrNoRelease) {
		fmt.Printf("easm-agent %s: %v.\n", version, err)
		return nil
	}
	if err != nil {
		return err
	}
	if !u.IsNewer(r) {
		fmt.Printf("easm-agent %s is the latest release.\n", version)
		return nil
	}
	fmt.Printf("easm-agent %s is available (you are running %s).\nRelease notes: %s\n", r.Version, version, r.URL)
	if u.CanInstall() {
		fmt.Println("Install it with:  easm-agent -update   (or from System health → Updates)")
	} else {
		fmt.Println("This build cannot verify updates; download the new version from the release page.")
	}
	return nil
}

// updateCommand implements -update and -rollback for the program file this process
// was started from. A service is stopped around the swap and started again; an agent
// running in a console must be stopped first (or updated from its web interface).
func updateCommand(boot *Bootstrap, svc service.Service, rollback, yes bool) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	running := false
	if st, err := svc.Status(); err == nil && st == service.StatusRunning {
		running = true
	} else {
		lock, err := LockDataDir(boot.DataDir)
		if err != nil {
			return fmt.Errorf("the agent is running in a console, not as a service. Update it from System health → Updates, or stop it and run this again: %w", err)
		}
		defer lock.Release()
	}

	if rollback {
		return withServiceStopped(svc, running, func() error {
			if err := Rollback(exe); err != nil {
				return err
			}
			fmt.Println("Rolled back to the version before the last update (the newer one is kept as " + filepath.Base(exe) + ".rolledback).")
			return nil
		})
	}

	u := NewUpdater()
	if !u.CanInstall() {
		return ErrNoVerificationKey
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r, err := u.Latest(ctx)
	if err != nil {
		return err
	}
	if !u.IsNewer(r) {
		fmt.Printf("easm-agent %s is the latest release; nothing to do.\n", version)
		return nil
	}
	fmt.Printf("easm-agent %s is available (running %s).\nRelease notes: %s\n", r.Version, version, r.URL)
	if !yes {
		_, _ = fmt.Fprint(os.Stderr, "Install it now? Take a backup first if you have not (Settings → Backup). [y/N] ")
		ans, _ := readLine(stdinLines())
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return errors.New("not installed")
		}
	}
	fmt.Println("Downloading and verifying the signed release...")
	file, err := u.Fetch(ctx, r, filepath.Dir(exe))
	if err != nil {
		return err
	}
	err = withServiceStopped(svc, running, func() error { return ReplaceExecutable(exe, file) })
	if err != nil {
		_ = os.Remove(file)
		return err
	}
	fmt.Printf("Installed easm-agent %s. The previous version is kept as %s.old (easm-agent -rollback to go back).\n", r.Version, filepath.Base(exe))
	return nil
}

// withServiceStopped runs fn with the service stopped when it was running, then starts it again.
func withServiceStopped(svc service.Service, running bool, fn func() error) error {
	if !running {
		return fn()
	}
	fmt.Println("Stopping the service...")
	if err := svc.Stop(); err != nil {
		return fmt.Errorf("stopping the service (run this from an elevated prompt / as root): %w", err)
	}
	for i := 0; i < 60; i++ {
		if st, err := svc.Status(); err == nil && st != service.StatusRunning {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	ferr := fn()
	fmt.Println("Starting the service...")
	if err := svc.Start(); err != nil {
		return errors.Join(ferr, fmt.Errorf("starting the service again: %w (start it with easm-agent -service start)", err))
	}
	return ferr
}

// restartAfterUpdate starts the newly installed program in its own console window
// (where it asks for the key passphrase if there is one) and stops this one. The new
// process waits for this one to release the data folder (-after-update).
func (p *program) restartAfterUpdate() {
	p.stopOnce.Do(func() {
		go func() {
			time.Sleep(time.Second) // let the confirmation page reach the browser
			exe, err := os.Executable()
			if err == nil {
				var args []string
				for _, a := range os.Args[1:] {
					if a != "-after-update" && a != "--after-update" {
						args = append(args, a)
					}
				}
				cmd := exec.Command(exe, append(args, "-after-update")...) //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- G204: exe is os.Executable() (this program restarting itself) and args are its own command line; no outside input
				inNewConsole(cmd)
				if err = cmd.Start(); err == nil {
					p.log.Info("restarting into the updated program", "pid", cmd.Process.Pid)
				}
			}
			if err != nil {
				p.log.Error("could not start the updated program; start it by hand", "err", err)
			}
			_ = p.Stop(nil)
			os.Exit(0)
		}()
	})
}
