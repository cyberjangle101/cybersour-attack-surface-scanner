//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/term"
)

// inNewConsole gives cmd a console window of its own, as a double-click would.
// os/exec still hands the child NUL for its standard handles, so the child calls
// useOwnConsole to read and write that window.
func inNewConsole(cmd *exec.Cmd) {
	const createNewConsole = 0x00000010
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole}
}

// useOwnConsole points stdin, stdout and stderr at this process's console window
// when they are not attached to it. An agent restarted by an update gets NUL for
// all three, so without this it could not ask for the key passphrase and would
// exit straight away with nothing on screen.
func useOwnConsole() {
	if hwnd, _, _ := procGetConsoleWindow.Call(); procGetConsoleWindow.Find() != nil || hwnd == 0 {
		return
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if in, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
			os.Stdin = in
		}
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		if out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
			os.Stdout, os.Stderr = out, out
		}
	}
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow    = kernel32.NewProc("GetConsoleWindow")
	procGetConsoleProcesses = kernel32.NewProc("GetConsoleProcessList")
	procShowWindow          = user32.NewProc("ShowWindow")
)

const swHide = 0

// ownsConsole reports whether this process is alone on its console window, which
// is the case when the program was started by double-clicking it. When it was
// started from cmd or PowerShell the shell shares the console and hiding it would
// hide the user's terminal.
func ownsConsole() bool {
	if procGetConsoleWindow.Find() != nil || procGetConsoleProcesses.Find() != nil {
		return false
	}
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd == 0 {
		return false
	}
	var pids [4]uint32
	n, _, _ := procGetConsoleProcesses.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// hideConsole hides this process's console window; the agent keeps running.
func hideConsole() bool {
	if procShowWindow.Find() != nil {
		return false
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return false
	}
	_, _, _ = procShowWindow.Call(hwnd, swHide)
	return true
}
