// Command icon draws the EASM Agent logo and writes it where the program uses it:
//
//	rsrc_windows_amd64.syso  the Windows icon resource linked into easm-agent.exe
//	                         (Explorer, the taskbar and the notification-area icon)
//	web/static/favicon.png   the browser-tab icon of the web interface
//
// The logo is drawn from code, so the committed files can be reproduced and
// reviewed: a radar sweep with one amber contact on a blue tile ("scanning the
// external attack surface"). Run from the repository root after changing it:
//
//	go run ./tools/icon
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 256}
	var frames [][]byte
	for _, s := range sizes {
		b, err := encodePNG(draw(s))
		if err != nil {
			fail(err)
		}
		frames = append(frames, b)
	}
	if err := os.WriteFile("rsrc_windows_amd64.syso", iconObject(sizes, frames), 0o644); err != nil { //nolint:gosec // G306: a source file of the repository
		fail(err)
	}
	fav, err := encodePNG(draw(32))
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile("web/static/favicon.png", fav, 0o644); err != nil { //nolint:gosec // G306: a source file of the repository
		fail(err)
	}
	fmt.Println("wrote rsrc_windows_amd64.syso and web/static/favicon.png")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "icon:", err)
	os.Exit(1)
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	err := enc.Encode(&buf, img)
	return buf.Bytes(), err
}

type rgba struct{ r, g, b, a float64 } // premultiplied, 0..1

// over draws c (straight colour, alpha a) on top of dst.
func over(dst rgba, r, g, b, a float64) rgba {
	return rgba{r*a + dst.r*(1-a), g*a + dst.g*(1-a), b*a + dst.b*(1-a), a + dst.a*(1-a)}
}

// draw renders the logo at size×size pixels, averaging several samples per pixel for smooth edges.
func draw(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	k := 6
	if size > 64 {
		k = 3
	}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sum rgba
			for sy := 0; sy < k; sy++ {
				for sx := 0; sx < k; sx++ {
					u := (float64(px) + (float64(sx)+0.5)/float64(k)) / float64(size)
					v := (float64(py) + (float64(sy)+0.5)/float64(k)) / float64(size)
					c := sample(u, v, size)
					sum.r, sum.g, sum.b, sum.a = sum.r+c.r, sum.g+c.g, sum.b+c.b, sum.a+c.a
				}
			}
			n := float64(k * k)
			a := sum.a / n
			if a <= 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{to8(sum.r / n / a), to8(sum.g / n / a), to8(sum.b / n / a), to8(a)})
		}
	}
	return img
}

func to8(f float64) uint8 { return uint8(math.Round(math.Max(0, math.Min(1, f)) * 255)) }

// sample is the logo's colour at (u, v) in the unit square (v grows downwards).
func sample(u, v float64, size int) rgba {
	var c rgba
	// Blue tile with rounded corners, lighter at the top.
	if roundedBox(u-0.5, v-0.5, 0.46, 0.2) > 0 {
		return c
	}
	t := v
	c = over(c, lerp(37, 30, t)/255, lerp(99, 58, t)/255, lerp(235, 138, t)/255, 1)

	dx, dy := u-0.5, v-0.5
	rho := math.Hypot(dx, dy)
	ang := math.Atan2(dy, dx) * 180 / math.Pi // 0 = right, -90 = up
	// Radar sweep: a wedge from straight up to the upper right, brightest at its leading edge.
	const from, to = -100.0, -30.0
	if rho <= 0.34 && ang >= from && ang <= to {
		c = over(c, 1, 1, 1, 0.55*(ang-from)/(to-from))
	}
	// Range rings and the centre.
	if math.Abs(rho-0.32) <= 0.037 {
		c = over(c, 1, 1, 1, 1)
	}
	if size > 20 && math.Abs(rho-0.18) <= 0.028 {
		c = over(c, 1, 1, 1, 0.85)
	}
	if rho <= 0.06 {
		c = over(c, 1, 1, 1, 1)
	}
	// The contact: an amber dot on the sweep's leading edge.
	bx, by := 0.5+0.245*math.Cos(-50*math.Pi/180), 0.5+0.245*math.Sin(-50*math.Pi/180)
	if math.Hypot(u-bx, v-by) <= 0.065 {
		c = over(c, 245.0/255, 158.0/255, 11.0/255, 1)
	}
	return c
}

func lerp(a, b, t float64) float64 { return a + (b-a)*t }

// roundedBox is the signed distance from (x, y) to a square of half-width h with corner radius r (negative inside).
func roundedBox(x, y, h, r float64) float64 {
	qx, qy := math.Abs(x)-(h-r), math.Abs(y)-(h-r)
	out := math.Hypot(math.Max(qx, 0), math.Max(qy, 0))
	return out + math.Min(math.Max(qx, qy), 0) - r
}

// iconObject builds a COFF object file holding one icon group (resource ID 1) made
// of the given PNG frames, in the layout the Go linker merges into a program's
// .rsrc section. PNG frames are understood by Windows Vista and later.
func iconObject(sizes []int, frames [][]byte) []byte {
	n := len(frames)
	le := binary.LittleEndian
	dir := func(b []byte, ids []uint32, offs []uint32, sub bool) []byte {
		hdr := make([]byte, 16)
		le.PutUint16(hdr[14:], uint16(len(ids))) // all entries are numeric IDs
		b = append(b, hdr...)
		for i, id := range ids {
			e := make([]byte, 8)
			le.PutUint32(e, id)
			o := offs[i]
			if sub {
				o |= 0x80000000
			}
			le.PutUint32(e[4:], o)
			b = append(b, e...)
		}
		return b
	}
	// Offsets of each part, in the order they are laid out.
	const dirSize = 16
	rootOff := uint32(0)
	iconTypeOff := rootOff + dirSize + 2*8
	groupTypeOff := iconTypeOff + dirSize + uint32(n)*8
	langOff := groupTypeOff + dirSize + 8 // n icon language dirs, then the group's
	dataEntryOff := langOff + uint32(n+1)*(dirSize+8)
	blobOff := dataEntryOff + uint32(n+1)*16

	group := make([]byte, 6+14*n)
	le.PutUint16(group[2:], 1) // type: icon
	le.PutUint16(group[4:], uint16(n))
	for i, s := range sizes {
		e := group[6+14*i:]
		if s < 256 {
			e[0], e[1] = byte(s), byte(s)
		}
		le.PutUint16(e[4:], 1)  // planes
		le.PutUint16(e[6:], 32) // bits per pixel
		le.PutUint32(e[8:], uint32(len(frames[i])))
		le.PutUint16(e[12:], uint16(i+1)) // the RT_ICON resource ID
	}
	blobs := append(append([][]byte{}, frames...), group)
	blobAt := make([]uint32, len(blobs))
	at := blobOff
	for i, b := range blobs {
		blobAt[i] = at
		at += uint32((len(b) + 7) &^ 7)
	}

	var sec []byte
	sec = dir(sec, []uint32{3, 14}, []uint32{iconTypeOff, groupTypeOff}, true) // RT_ICON, RT_GROUP_ICON
	ids, offs := make([]uint32, n), make([]uint32, n)
	for i := range ids {
		ids[i], offs[i] = uint32(i+1), langOff+uint32(i)*(dirSize+8)
	}
	sec = dir(sec, ids, offs, true)
	sec = dir(sec, []uint32{1}, []uint32{langOff + uint32(n)*(dirSize+8)}, true)
	for i := 0; i <= n; i++ {
		sec = dir(sec, []uint32{0x0409}, []uint32{dataEntryOff + uint32(i)*16}, false) // en-US
	}
	var relocs []uint32 // offsets of the OffsetToData fields, which hold section-relative addresses
	for i, b := range blobs {
		e := make([]byte, 16)
		le.PutUint32(e, blobAt[i])
		le.PutUint32(e[4:], uint32(len(b)))
		relocs = append(relocs, uint32(len(sec)))
		sec = append(sec, e...)
	}
	for _, b := range blobs {
		sec = append(sec, b...)
		for len(sec)%8 != 0 {
			sec = append(sec, 0)
		}
	}

	const fileHdr, secHdr = 20, 40
	rawAt := uint32(fileHdr + secHdr)
	relAt := rawAt + uint32(len(sec))
	symAt := relAt + uint32(len(relocs))*10
	var out []byte
	h := make([]byte, fileHdr)
	le.PutUint16(h[0:], 0x8664) // AMD64
	le.PutUint16(h[2:], 1)      // one section
	le.PutUint32(h[8:], symAt)
	le.PutUint32(h[12:], 1) // one symbol
	out = append(out, h...)
	s := make([]byte, secHdr)
	copy(s, ".rsrc")
	le.PutUint32(s[16:], uint32(len(sec)))
	le.PutUint32(s[20:], rawAt)
	le.PutUint32(s[24:], relAt)
	le.PutUint16(s[32:], uint16(len(relocs)))
	le.PutUint32(s[36:], 0x40000040) // initialised data, readable
	out = append(out, s...)
	out = append(out, sec...)
	for _, r := range relocs {
		e := make([]byte, 10)
		le.PutUint32(e, r)
		le.PutUint32(e[4:], 0) // symbol 0: the section itself
		le.PutUint16(e[8:], 3) // IMAGE_REL_AMD64_ADDR32NB
		out = append(out, e...)
	}
	sym := make([]byte, 18)
	copy(sym, ".rsrc")
	le.PutUint16(sym[12:], 1) // section number
	sym[16] = 3               // storage class: static
	out = append(out, sym...)
	out = append(out, 4, 0, 0, 0) // empty string table
	return out
}
