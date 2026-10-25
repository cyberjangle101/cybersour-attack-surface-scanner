//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiSupported is true: Windows can tie the key file to the account the agent runs as.
const dpapiSupported = true

// dpapiEntropy ties the protected blob to this use, so another program running as the
// same account cannot hand it to DPAPI without also knowing this string.
var dpapiEntropy = []byte("EASM Agent master key, DPAPI v3")

// dpapiProtect encrypts data with the Data Protection API under the current Windows
// account: only that account, on this computer, can decrypt it.
func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("nothing to protect")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	ent := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

// dpapiUnprotect reverses dpapiProtect; it fails for any other account or computer.
func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty protected key")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	ent := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

// takeBlob copies a DATA_BLOB that Windows allocated and frees the original, wiping it first.
func takeBlob(b *windows.DataBlob) []byte {
	if b.Data == nil || b.Size == 0 {
		return nil
	}
	src := unsafe.Slice(b.Data, b.Size)
	out := make([]byte, len(src))
	copy(out, src)
	clear(src)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

// windowsAccount names the account the process runs as, for messages ("DOMAIN\user", "NT SERVICE\easm-agent").
func windowsAccount() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "this Windows account"
	}
	acct, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String()
	}
	if dom == "" {
		return acct
	}
	return dom + `\` + acct
}
