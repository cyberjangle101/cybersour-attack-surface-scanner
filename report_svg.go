package main

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// Charts for the report page. They are plain inline SVG built from numbers and escaped text, so
// they need no script and satisfy the strict content-security policy; colours come from CSS classes.

var sevOrder = []string{"high", "medium", "low", "info"}

func esc(s string) string { return html.EscapeString(s) }

// donutSVG draws open findings by severity as a ring with the total in the middle.
func donutSVG(by map[string]int) template.HTML {
	total := 0
	for _, s := range sevOrder {
		total += by[s]
	}
	const cx, cy, r, w = 80.0, 80.0, 60.0, 22.0
	var b strings.Builder
	b.WriteString(`<svg class="chart donut" viewBox="0 0 160 160" role="img" aria-label="Open findings by severity">`)
	if total == 0 {
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="%.0f" class="ring-empty" fill="none" stroke-width="%.0f"/>`, cx, cy, r, w)
		fmt.Fprintf(&b, `<text x="80" y="86" class="big" text-anchor="middle">0</text>`)
	} else {
		angle := -math.Pi / 2
		for _, s := range sevOrder {
			n := by[s]
			if n == 0 {
				continue
			}
			frac := float64(n) / float64(total)
			if frac > 0.9999 {
				fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="%.0f" class="s-%s" fill="none" stroke-width="%.0f"><title>%s: %d</title></circle>`, cx, cy, r, s, w, s, n)
				angle += 2 * math.Pi
				continue
			}
			end := angle + frac*2*math.Pi
			x1, y1 := cx+r*math.Cos(angle), cy+r*math.Sin(angle)
			x2, y2 := cx+r*math.Cos(end), cy+r*math.Sin(end)
			large := 0
			if frac > 0.5 {
				large = 1
			}
			fmt.Fprintf(&b, `<path d="M %.2f %.2f A %.0f %.0f 0 %d 1 %.2f %.2f" class="s-%s" fill="none" stroke-width="%.0f"><title>%s: %d</title></path>`,
				x1, y1, r, r, large, x2, y2, s, w, s, n)
			angle = end
		}
		fmt.Fprintf(&b, `<text x="80" y="88" class="big" text-anchor="middle">%d</text>`, total)
	}
	b.WriteString(`<text x="80" y="104" class="small" text-anchor="middle">open</text></svg>`)
	return template.HTML(b.String()) //nolint:gosec // G203: built from numbers and fixed class names
}

// legendHTML is the key for the donut.
func legendHTML(by map[string]int) template.HTML {
	var b strings.Builder
	b.WriteString(`<ul class="legend">`)
	for _, s := range sevOrder {
		fmt.Fprintf(&b, `<li><span class="sw bg-%s"></span>%s <strong>%d</strong></li>`, s, strings.ToUpper(s[:1])+s[1:], by[s])
	}
	b.WriteString(`</ul>`)
	return template.HTML(b.String()) //nolint:gosec // G203: built from fixed words and numbers
}

// trendSVG draws new (red) against resolved (green) findings per day or week.
func trendSVG(tb []TrendBucket) template.HTML {
	const W, H, padL, padB, padT = 560.0, 190.0, 30.0, 26.0, 14.0
	maxV := 1
	for _, t := range tb {
		maxV = maxInt(maxV, maxInt(t.New, t.Resolved))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart trend" viewBox="0 0 %.0f %.0f" role="img" aria-label="New and resolved findings over time">`, W, H)
	plotH := H - padB - padT
	for i := 0; i <= 2; i++ {
		y := padT + plotH - plotH*float64(i)/2
		fmt.Fprintf(&b, `<line x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f" class="grid"/><text x="%.0f" y="%.1f" class="small" text-anchor="end">%d</text>`,
			padL, y, W-4, y, padL-4, y+3, int(math.Ceil(float64(maxV)*float64(i)/2)))
	}
	n := len(tb)
	slot := (W - padL - 6) / float64(maxInt(n, 1))
	bw := math.Min(slot/2.6, 22)
	step := 1
	if n > 14 {
		step = (n + 13) / 14
	}
	for i, t := range tb {
		x := padL + slot*float64(i) + slot/2
		hn := plotH * float64(t.New) / float64(maxV)
		hr := plotH * float64(t.Resolved) / float64(maxV)
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="bg-new"><title>%s: %d new</title></rect>`, x-bw-1, padT+plotH-hn, bw, hn, esc(t.Label), t.New)
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="bg-fixed"><title>%s: %d resolved</title></rect>`, x+1, padT+plotH-hr, bw, hr, esc(t.Label), t.Resolved)
		if i%step == 0 {
			fmt.Fprintf(&b, `<text x="%.1f" y="%.0f" class="small" text-anchor="middle">%s</text>`, x, H-8, esc(t.Label))
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // G203: numbers and escaped labels only
}

// barItem is one row of a horizontal bar chart.
type barItem struct {
	Label string
	Value int
	Class string // s-high | s-medium | s-low | s-info | bar-neutral
}

// hbarSVG draws labelled horizontal bars.
func hbarSVG(items []barItem, label string) template.HTML {
	if len(items) == 0 {
		return template.HTML(`<p class="muted small">Nothing to show.</p>`) //nolint:gosec // G203: constant text
	}
	const W, rowH, labelW = 380.0, 24.0, 150.0
	maxV := 1
	for _, it := range items {
		maxV = maxInt(maxV, it.Value)
	}
	H := rowH*float64(len(items)) + 6
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart hbar" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s">`, W, H, esc(label))
	for i, it := range items {
		y := rowH*float64(i) + 3
		bw := (W - labelW - 40) * float64(it.Value) / float64(maxV)
		if bw < 2 {
			bw = 2
		}
		fmt.Fprintf(&b, `<text x="0" y="%.1f" class="lbl">%s</text>`, y+15, esc(ellipsize(it.Label, 24)))
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.1f" width="%.1f" height="%.0f" rx="3" class="%s"><title>%s: %d</title></rect>`, labelW, y+3, bw, rowH-10, esc(it.Class), esc(it.Label), it.Value)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="small">%d</text>`, labelW+bw+6, y+15, it.Value)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // G203: numbers and escaped labels only
}

func ellipsize(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// categoryBars and assetBars adapt the summary to hbarSVG.
func categoryBars(c []CatCount) []barItem {
	out := make([]barItem, len(c))
	for i, x := range c {
		cls := "bar-neutral"
		if x.High > 0 {
			cls = "s-high"
		}
		out[i] = barItem{x.Name, x.Count, cls}
	}
	return out
}

func assetBars(a []AssetCount) []barItem {
	out := make([]barItem, len(a))
	for i, x := range a {
		out[i] = barItem{x.Host, x.Count, "s-" + strings.ToLower(x.Max)}
	}
	return out
}
