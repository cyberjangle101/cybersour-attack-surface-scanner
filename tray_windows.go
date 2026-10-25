//go:build windows

package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// The notification-area ("system tray") icon of an interactive agent on Windows.
//
// Once the console window has closed, the icon is how a person at the desktop can
// tell the agent is running and what it is: it shows the EASM Agent logo (the
// program's own icon resource, see rsrc_windows_amd64.syso and tools/icon), a
// tooltip with the version and address, and a menu to open the dashboard, open the
// log file or stop the agent. It is drawn with plain Win32 calls, so no extra
// library is needed.

// trayOptions configures the notification-area icon.
type trayOptions struct {
	Tip     string        // tooltip: name, version and address
	Notice  string        // shown once as a notification when the icon appears ("" = none)
	Open    func()        // left click, or "Open EASM Agent"
	Stop    func()        // "Stop EASM Agent", after a confirmation
	LogFile func() string // the file "Open log file" opens
}

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	shell32            = syscall.NewLazyDLL("shell32.dll")
	procRegisterClass  = user32.NewProc("RegisterClassExW")
	procCreateWindow   = user32.NewProc("CreateWindowExW")
	procDestroyWindow  = user32.NewProc("DestroyWindow")
	procDefWindowProc  = user32.NewProc("DefWindowProcW")
	procGetMessage     = user32.NewProc("GetMessageW")
	procTranslateMsg   = user32.NewProc("TranslateMessage")
	procDispatchMsg    = user32.NewProc("DispatchMessageW")
	procPostMessage    = user32.NewProc("PostMessageW")
	procPostQuit       = user32.NewProc("PostQuitMessage")
	procRegisterMsg    = user32.NewProc("RegisterWindowMessageW")
	procLoadImage      = user32.NewProc("LoadImageW")
	procLoadIcon       = user32.NewProc("LoadIconW")
	procGetSysMetrics  = user32.NewProc("GetSystemMetrics")
	procCreatePopup    = user32.NewProc("CreatePopupMenu")
	procAppendMenu     = user32.NewProc("AppendMenuW")
	procSetDefaultItem = user32.NewProc("SetMenuDefaultItem")
	procTrackPopup     = user32.NewProc("TrackPopupMenu")
	procDestroyMenu    = user32.NewProc("DestroyMenu")
	procGetCursorPos   = user32.NewProc("GetCursorPos")
	procSetForeground  = user32.NewProc("SetForegroundWindow")
	procMessageBox     = user32.NewProc("MessageBoxW")
	procNotifyIcon     = shell32.NewProc("Shell_NotifyIconW")
	procGetModule      = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmNull         = 0x0000
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmContextMenu  = 0x007B
	wmLButtonUp    = 0x0202
	wmRButtonUp    = 0x0205
	wmApp          = 0x8000
	trayCallback   = wmApp + 1
	nimAdd         = 0
	nimModify      = 1
	nimDelete      = 2
	nifMessage     = 0x01
	nifIcon        = 0x02
	nifTip         = 0x04
	nifInfo        = 0x10
	niifUser       = 0x04
	imageIcon      = 1
	smCxSmIcon     = 49
	idiApplication = 32512
	mfString       = 0x0000
	mfGrayed       = 0x0001
	mfSeparator    = 0x0800
	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100
	mbYesNo        = 0x0004
	mbIconQuestion = 0x0020
	mbSetForegr    = 0x00010000
	idYes          = 6
	errClassExists = 1410

	menuOpen = 1
	menuLog  = 2
	menuStop = 3
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	TimeoutVersion  uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        [16]byte
	BalloonIcon     uintptr
}

type point struct{ X, Y int32 }

type msgT struct {
	Wnd     uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

// trayState is the one icon of this process; the window procedure finds it here.
type trayState struct {
	opts       trayOptions
	log        *slog.Logger
	wnd, icon  uintptr
	taskbarMsg uintptr // "TaskbarCreated": Explorer restarted and the icon must be added again
	lastOpen   time.Time
	done       chan struct{}
	stopOnce   sync.Once
}

var (
	theTray      atomic.Pointer[trayState]
	trayProcOnce sync.Once
	trayProc     uintptr
)

// startTray shows the icon and returns a function that removes it, or nil when
// there is no desktop to show it on (the reason is logged).
func startTray(opts trayOptions, log *slog.Logger) func() {
	if theTray.Load() != nil {
		return nil
	}
	t := &trayState{opts: opts, log: log, done: make(chan struct{})}
	ready := make(chan error, 1)
	go t.run(ready)
	if err := <-ready; err != nil {
		log.Info("no notification-area icon", "reason", err)
		return nil
	}
	return t.stop
}

// run owns the icon's window: Win32 windows belong to the thread that made them.
func (t *trayState) run(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(t.done)
	if err := t.create(); err != nil {
		ready <- err
		return
	}
	theTray.Store(t)
	ready <- nil
	var m msgT
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0 = WM_QUIT, -1 = error
			return
		}
		_, _, _ = procTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (t *trayState) create() error {
	if err := procNotifyIcon.Find(); err != nil {
		return err
	}
	trayProcOnce.Do(func() { trayProc = syscall.NewCallback(trayWndProc) })
	inst, _, _ := procGetModule.Call(0)
	class := utf16("EASMAgentTray")
	wc := wndClassEx{WndProc: trayProc, Instance: inst, ClassName: class}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		if en, ok := err.(syscall.Errno); !ok || en != errClassExists {
			return err
		}
	}
	// A hidden top-level window (not message-only: the menu needs a window that can be brought to the front).
	wnd, _, err := procCreateWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(utf16("EASM Agent"))),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if wnd == 0 {
		return err
	}
	t.wnd = wnd
	t.taskbarMsg, _, _ = procRegisterMsg.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	size, _, _ := procGetSysMetrics.Call(smCxSmIcon)
	t.icon, _, _ = procLoadImage.Call(inst, 1, imageIcon, size, size, 0) // icon group 1 of this program
	if t.icon == 0 {
		t.icon, _, _ = procLoadIcon.Call(0, idiApplication)
	}
	if !t.notify(nimAdd, t.opts.Notice) {
		_, _, _ = procDestroyWindow.Call(wnd)
		return errors.New("the notification area did not accept the icon")
	}
	return nil
}

// notify adds, updates or removes the icon; notice, when set, is shown once as a notification.
func (t *trayState) notify(op uintptr, notice string) bool {
	d := notifyIconData{Wnd: t.wnd, ID: 1, Flags: nifMessage | nifIcon | nifTip, CallbackMessage: trayCallback, Icon: t.icon}
	d.Size = uint32(unsafe.Sizeof(d))
	copyUTF16(d.Tip[:], t.opts.Tip)
	if notice != "" {
		d.Flags |= nifInfo
		d.InfoFlags = niifUser
		d.BalloonIcon = t.icon
		copyUTF16(d.Info[:], notice)
		copyUTF16(d.InfoTitle[:], "EASM Agent")
	}
	r, _, _ := procNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
	return r != 0
}

func trayWndProc(wnd, msg, wParam, lParam uintptr) uintptr {
	t := theTray.Load()
	if t != nil && wnd == t.wnd {
		switch {
		case msg == trayCallback:
			switch lParam & 0xFFFF { // the mouse message, in the original callback format
			case wmLButtonUp:
				if time.Since(t.lastOpen) > 2*time.Second { // a double click must not open two tabs
					t.lastOpen = time.Now()
					go t.opts.Open()
				}
			case wmRButtonUp, wmContextMenu:
				t.menu()
			}
			return 0
		case msg == t.taskbarMsg && msg != 0:
			t.notify(nimAdd, "")
			return 0
		case msg == wmDestroy:
			t.notify(nimDelete, "")
			_, _, _ = procPostQuit.Call(0)
			return 0
		}
	}
	r, _, _ := procDefWindowProc.Call(wnd, msg, wParam, lParam)
	return r
}

// menu shows the right-click menu at the pointer and carries out the choice.
func (t *trayState) menu() {
	m, _, _ := procCreatePopup.Call()
	if m == 0 {
		return
	}
	defer func() { _, _, _ = procDestroyMenu.Call(m) }()
	logFile := t.opts.LogFile()
	logFlags := uintptr(mfString)
	if _, err := os.Stat(logFile); err != nil {
		logFlags |= mfGrayed // nothing written to a file yet (the console is still open)
	}
	_, _, _ = procAppendMenu.Call(m, mfString, menuOpen, uintptr(unsafe.Pointer(utf16("Open EASM Agent"))))
	_, _, _ = procAppendMenu.Call(m, logFlags, menuLog, uintptr(unsafe.Pointer(utf16("Open log file"))))
	_, _, _ = procAppendMenu.Call(m, mfSeparator, 0, 0)
	_, _, _ = procAppendMenu.Call(m, mfString, menuStop, uintptr(unsafe.Pointer(utf16("Stop EASM Agent"))))
	_, _, _ = procSetDefaultItem.Call(m, menuOpen, 0)
	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForeground.Call(t.wnd) // so the menu closes when the user clicks elsewhere
	cmd, _, _ := procTrackPopup.Call(m, tpmRightButton|tpmNoNotify|tpmReturnCmd, uintptr(pt.X), uintptr(pt.Y), 0, t.wnd, 0)
	_, _, _ = procPostMessage.Call(t.wnd, wmNull, 0, 0)
	switch cmd {
	case menuOpen:
		go t.opts.Open()
	case menuLog:
		cmd := exec.Command("notepad.exe", logFile) //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- G204: Notepad on the agent's own log file; no outside input
		if err := cmd.Start(); err == nil {
			go func() { _ = cmd.Wait() }()
		}
	case menuStop:
		r, _, _ := procMessageBox.Call(t.wnd,
			uintptr(unsafe.Pointer(utf16("Stop EASM Agent?\n\nScans, alerts and the web interface stop until the agent is started again."))),
			uintptr(unsafe.Pointer(utf16("EASM Agent"))), mbYesNo|mbIconQuestion|mbSetForegr)
		if r == idYes {
			t.log.Info("stop requested from the notification-area icon")
			go t.opts.Stop()
		}
	}
}

// stop removes the icon and ends its thread.
func (t *trayState) stop() {
	t.stopOnce.Do(func() {
		_, _, _ = procPostMessage.Call(t.wnd, wmClose, 0, 0)
		select {
		case <-t.done:
		case <-time.After(2 * time.Second):
		}
	})
}

// utf16 converts s for a Win32 call; s never holds a NUL here.
func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// copyUTF16 copies s into a fixed, NUL-terminated buffer, cutting it to fit.
func copyUTF16(dst []uint16, s string) {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}
