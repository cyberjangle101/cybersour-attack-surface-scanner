//go:build !windows

package main

import "errors"

// dpapiSupported is false: the Windows Data Protection API exists only on Windows.
const dpapiSupported = false

var errNoDPAPI = errors.New("protecting the key with the Windows account is only possible on Windows")

func dpapiProtect([]byte) ([]byte, error)   { return nil, errNoDPAPI }
func dpapiUnprotect([]byte) ([]byte, error) { return nil, errNoDPAPI }
func windowsAccount() string                { return "" }
