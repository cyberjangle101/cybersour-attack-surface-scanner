package main

// releasePublicKey is the Ed25519 public key (base64) that official releases are
// signed with. Updates are installed only when SHA256SUMS carries a valid signature
// from the matching private key, which exists only as the EASM_RELEASE_SIGNING_KEY
// secret of the release workflow. Empty means this build cannot verify updates and
// will only report them. Create the pair with:  go run ./tools/release keygen
// (see RELEASING.md). Release builds may also set it with
// -ldflags "-X main.releasePublicKey=...".
var releasePublicKey = "9TdACkVTqurKtz3jJCccdMFKUL+j1uN1nIZ9UsE/EUA="
