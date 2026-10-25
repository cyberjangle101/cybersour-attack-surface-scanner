//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// inNewConsole gives cmd a console window of its own, as a double-click would.
func inNewConsole(cmd *exec.Cmd) {
	const createNewConsole = 0x00000010
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole}
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
