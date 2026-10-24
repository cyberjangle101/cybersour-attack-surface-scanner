package main

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// A real PDF (not "print to PDF"): an executive page with charts first, then the detail for the
// security team. It is drawn directly with the PDF library, so it needs no browser and looks the same
// everywhere. Text is limited to what the built-in PDF fonts can show (Western European characters);
// anything else is replaced by "?" rather than breaking the file.

type rgb struct{ r, g, b int }

var (
	pdfInk     = rgb{31, 41, 51}
	pdfMuted   = rgb{97, 111, 126}
	pdfLine    = rgb{217, 226, 236}
	pdfPanel   = rgb{240, 244, 248}
	pdfNavy    = rgb{16, 42, 67}
	pdfSev     = map[string]rgb{"high": {180, 35, 24}, "medium": {217, 119, 6}, "low": {37, 99, 235}, "info": {107, 114, 128}}
	pdfNew     = rgb{220, 38, 38}
	pdfFixed   = rgb{22, 163, 74}
	pdfRatings = map[string]rgb{"good": {22, 101, 52}, "warn": {146, 64, 14}, "bad": {153, 27, 27}}
)

const (
	pdfMargin = 15.0
	pdfWidth  = 180.0 // A4 minus margins
	pdfBottom = 280.0
	rowCap    = 400 // rows printed per table before pointing at the CSV export
)

type pdfDoc struct {
	p  *fpdf.Fpdf
	tr func(string) string
}

type pdfCol struct {
	Title string
	W     float64
	Align string
}

type pdfCell struct {
	Text  string
	Color *rgb
	Bold  bool
	Mono  bool
}

// RenderReportPDF draws the report and returns the PDF bytes.
func RenderReportPDF(rep *Report, agent string) ([]byte, error) {
	p := fpdf.New("P", "mm", "A4", "")
	p.SetMargins(pdfMargin, pdfMargin, pdfMargin)
	p.SetAutoPageBreak(false, 0)
	p.SetTitle("External attack surface report: "+rep.Heading(), true)
	p.SetAuthor(rep.PreparedBy, true)
	p.SetCreator("EASM Agent "+agent, false)
	p.SetCreationDate(rep.Generated)
	p.AliasNbPages("{nb}")
	d := &pdfDoc{p: p, tr: p.UnicodeTranslatorFromDescriptor("")}
	p.SetFooterFunc(func() {
		p.SetY(-12)
		p.SetFont("Helvetica", "", 8)
		d.color(pdfMuted)
		p.CellFormat(pdfWidth/2, 5, d.tr(clip("EASM Agent "+agent+" · "+rep.Heading(), 70)), "", 0, "L", false, 0, "")
		p.CellFormat(pdfWidth/2, 5, fmt.Sprintf("Page %d of {nb}", p.PageNo()), "", 0, "R", false, 0, "")
	})

	p.AddPage()
	d.title(rep)
	d.exec(rep)
	if p.GetY() > 200 {
		p.AddPage()
	} else {
		p.Ln(6)
	}
	d.detail(rep)

	var buf bytes.Buffer
	if err := p.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *pdfDoc) color(c rgb)  { d.p.SetTextColor(c.r, c.g, c.b) }
func (d *pdfDoc) fill(c rgb)   { d.p.SetFillColor(c.r, c.g, c.b) }
func (d *pdfDoc) stroke(c rgb) { d.p.SetDrawColor(c.r, c.g, c.b) }

// ensure starts a new page when less than h millimetres remain.
func (d *pdfDoc) ensure(h float64) {
	if d.p.GetY()+h > pdfBottom {
		d.p.AddPage()
	}
}

func (d *pdfDoc) title(rep *Report) {
	p := d.p
	d.fill(pdfNavy)
	p.Rect(0, 0, 210, 46, "F")
	p.SetXY(pdfMargin, 7)
	d.color(rgb{255, 255, 255})
	p.SetFont("Helvetica", "", 10)
	p.Cell(pdfWidth, 5, "External Attack Surface Report")
	// Who the report belongs to comes first and largest.
	p.SetXY(pdfMargin, 13)
	p.SetFont("Helvetica", "B", 20)
	p.Cell(pdfWidth, 10, d.tr(clip(rep.Heading(), 48)))
	p.SetXY(pdfMargin, 24)
	p.SetFont("Helvetica", "", 10)
	p.Cell(pdfWidth, 5, d.tr(clip("Domains: "+rep.DomainList(), 110)))
	p.SetXY(pdfMargin, 30)
	p.Cell(pdfWidth, 5, d.tr(fmt.Sprintf("Last %s  ·  generated %s  ·  prepared by %s",
		periodWords(rep.Days), rep.Generated.Format("2006-01-02 15:04 MST"), clip(rep.PreparedBy, 60))))
	if rep.Filter.Sev != nil {
		p.SetXY(pdfMargin, 37)
		p.SetFont("Helvetica", "I", 9)
		p.Cell(pdfWidth, 5, d.tr("Detail sections show: "+rep.Filter.Label()))
	}
	p.SetY(52)
}

func periodWords(days int) string {
	switch days {
	case 1:
		return "24 hours"
	case 365:
		return "year"
	}
	return fmt.Sprintf("%d days", days)
}

func (d *pdfDoc) heading(txt string, size float64) {
	d.ensure(size/2 + 14)
	p := d.p
	p.SetFont("Helvetica", "B", size)
	d.color(pdfNavy)
	p.CellFormat(pdfWidth, size/2.2+2, d.tr(txt), "", 1, "L", false, 0, "")
	p.Ln(1)
}

func (d *pdfDoc) para(txt string, size float64, c rgb) {
	p := d.p
	p.SetFont("Helvetica", "", size)
	d.color(c)
	lines := p.SplitLines([]byte(d.tr(txt)), pdfWidth)
	d.ensure(float64(len(lines))*(size/2.2+1.2) + 2)
	p.MultiCell(pdfWidth, size/2.2+1.2, d.tr(txt), "", "L", false)
	p.Ln(1)
}

// ---------------------------------------------------------------- executive page

func (d *pdfDoc) exec(rep *Report) {
	p := d.p
	ex := rep.Exec
	d.heading("Executive summary", 16)

	// rating pill and score
	rc := pdfRatings[ex.RatingClass]
	x, y := p.GetX(), p.GetY()
	d.fill(rgb{rc.r, rc.g, rc.b})
	p.RoundedRect(x, y, 34, 9, 4.5, "1234", "F")
	p.SetXY(x, y+1.5)
	d.color(rgb{255, 255, 255})
	p.SetFont("Helvetica", "B", 12)
	p.CellFormat(34, 6, ex.Rating, "", 0, "C", false, 0, "")
	p.SetXY(x+38, y+2)
	d.color(pdfMuted)
	p.SetFont("Helvetica", "", 9)
	p.Cell(80, 5, fmt.Sprintf("posture score %d / 100", ex.Score))
	p.SetY(y + 13)

	d.para(ex.Headline, 11, pdfInk)
	p.Ln(1)

	// KPI tiles
	tiles := []struct {
		n int
		l string
	}{{ex.Domains, "Domains"}, {ex.Hosts, "Hosts"}, {ex.Open, "Open findings"}, {ex.OpenBySev["high"], "High severity"}, {ex.NewCount, "New"}, {ex.Resolved, "Fixed"}}
	tw := (pdfWidth - 5*3) / 6
	y = p.GetY()
	for i, t := range tiles {
		tx := pdfMargin + float64(i)*(tw+3)
		d.fill(pdfPanel)
		d.stroke(pdfLine)
		p.RoundedRect(tx, y, tw, 20, 2, "1234", "DF")
		p.SetXY(tx, y+3)
		if i == 3 && t.n > 0 {
			d.color(pdfSev["high"])
		} else {
			d.color(pdfInk)
		}
		p.SetFont("Helvetica", "B", 18)
		p.CellFormat(tw, 8, fmt.Sprint(t.n), "", 0, "C", false, 0, "")
		p.SetXY(tx, y+12)
		d.color(pdfMuted)
		p.SetFont("Helvetica", "", 8)
		p.CellFormat(tw, 5, t.l, "", 0, "C", false, 0, "")
	}
	p.SetY(y + 25)

	// charts, row 1: donut + trend
	y = p.GetY()
	d.sub(pdfMargin, y, "Open findings by severity")
	d.donut(pdfMargin+17, y+27, 16, 6, ex.OpenBySev)
	d.legend(pdfMargin+42, y+14, ex.OpenBySev)
	d.sub(pdfMargin+75, y, "New and fixed over time")
	d.trend(pdfMargin+75, y+7, 105, 36, ex.Trend)
	p.SetY(y + 56)

	if len(ex.TopRisks) > 0 {
		d.heading("Biggest risks", 13)
		rows := make([][]pdfCell, 0, len(ex.TopRisks))
		for _, t := range ex.TopRisks {
			c := pdfSev[strings.ToLower(t.Severity)]
			rows = append(rows, []pdfCell{{Text: strings.ToUpper(t.Severity), Color: &c, Bold: true}, {Text: t.Title, Bold: true}, {Text: fmt.Sprint(t.Assets)}, {Text: t.Risk}, {Text: t.Fix}})
		}
		d.table([]pdfCol{{"Severity", 18, "L"}, {"Risk", 38, "L"}, {"Assets", 14, "R"}, {"Why it matters", 54, "L"}, {"What to do", 56, "L"}}, rows, 8)
	}
	if len(ex.Actions) > 0 {
		d.heading("Priority actions", 13)
		for i, a := range ex.Actions {
			d.para(fmt.Sprintf("%d.  %s", i+1, a), 10, pdfInk)
		}
	}
	d.ensure(85)
	d.heading("Where the problems are", 13)
	y = p.GetY()
	d.sub(pdfMargin, y, "What kind of problems")
	d.hbars(pdfMargin, y+7, 84, categoryBars(ex.Categories))
	d.sub(pdfMargin+96, y, "Most affected assets")
	d.hbars(pdfMargin+96, y+7, 84, assetBars(ex.TopAssets))
	p.SetY(y + 7 + 6*float64(maxInt(maxInt(len(ex.Categories), len(ex.TopAssets)), 1)) + 6)

	d.para("How the score works: 100 minus 12 for each high-severity finding (up to 6), 4 for each medium (up to 10) and 1 for each low (up to 10). Good means nothing high or medium; Fair means medium findings or a single high; Poor means two or more high. Accepted risks are not counted.", 8, pdfMuted)
}

func (d *pdfDoc) sub(x, y float64, txt string) {
	d.p.SetXY(x, y)
	d.p.SetFont("Helvetica", "B", 10)
	d.color(pdfNavy)
	d.p.Cell(80, 5, d.tr(txt))
}

func (d *pdfDoc) legend(x, y float64, by map[string]int) {
	d.p.SetFont("Helvetica", "", 9)
	for i, s := range sevOrder {
		yy := y + float64(i)*6
		d.fill(pdfSev[s])
		d.p.Rect(x, yy+1, 3, 3, "F")
		d.p.SetXY(x+5, yy)
		d.color(pdfInk)
		d.p.Cell(26, 5, fmt.Sprintf("%s  %d", strings.ToUpper(s[:1])+s[1:], by[s]))
	}
}

// donut draws a ring made of filled polygons (the PDF library has no arc fill).
func (d *pdfDoc) donut(cx, cy, rOut, rIn float64, by map[string]int) {
	total := 0
	for _, s := range sevOrder {
		total += by[s]
	}
	if total == 0 {
		d.fill(pdfLine)
		d.p.Circle(cx, cy, rOut, "F")
		d.fill(rgb{255, 255, 255})
		d.p.Circle(cx, cy, rIn, "F")
	} else {
		a := -math.Pi / 2
		for _, s := range sevOrder {
			if by[s] == 0 {
				continue
			}
			sweep := 2 * math.Pi * float64(by[s]) / float64(total)
			steps := int(math.Ceil(sweep/(math.Pi/36))) + 1
			pts := make([]fpdf.PointType, 0, 2*steps+2)
			for i := 0; i <= steps; i++ {
				t := a + sweep*float64(i)/float64(steps)
				pts = append(pts, fpdf.PointType{X: cx + rOut*math.Cos(t), Y: cy + rOut*math.Sin(t)})
			}
			for i := steps; i >= 0; i-- {
				t := a + sweep*float64(i)/float64(steps)
				pts = append(pts, fpdf.PointType{X: cx + rIn*math.Cos(t), Y: cy + rIn*math.Sin(t)})
			}
			d.fill(pdfSev[s])
			d.stroke(pdfSev[s])
			d.p.SetLineWidth(0.1)
			d.p.Polygon(pts, "DF")
			a += sweep
		}
	}
	d.p.SetXY(cx-10, cy-5)
	d.color(pdfInk)
	d.p.SetFont("Helvetica", "B", 16)
	d.p.CellFormat(20, 7, fmt.Sprint(total), "", 0, "C", false, 0, "")
	d.p.SetXY(cx-10, cy+2)
	d.color(pdfMuted)
	d.p.SetFont("Helvetica", "", 7)
	d.p.CellFormat(20, 4, "open", "", 0, "C", false, 0, "")
}

// trend draws new (red) against fixed (green) bars.
func (d *pdfDoc) trend(x, y, w, h float64, tb []TrendBucket) {
	maxV := 1
	for _, t := range tb {
		maxV = maxInt(maxV, maxInt(t.New, t.Resolved))
	}
	plotH := h - 9
	d.stroke(pdfLine)
	d.p.SetLineWidth(0.2)
	d.p.Line(x, y+plotH, x+w, y+plotH)
	d.p.Line(x, y, x+w, y)
	d.p.SetFont("Helvetica", "", 6.5)
	d.color(pdfMuted)
	d.p.SetXY(x, y-3)
	d.p.Cell(8, 3, fmt.Sprint(maxV))
	n := maxInt(len(tb), 1)
	slot := w / float64(n)
	bw := math.Min(slot/2.5, 5)
	step := 1
	if n > 12 {
		step = (n + 11) / 12
	}
	for i, t := range tb {
		cx := x + slot*float64(i) + slot/2
		hn, hr := plotH*float64(t.New)/float64(maxV), plotH*float64(t.Resolved)/float64(maxV)
		d.fill(pdfNew)
		d.p.Rect(cx-bw-0.2, y+plotH-hn, bw, hn, "F")
		d.fill(pdfFixed)
		d.p.Rect(cx+0.2, y+plotH-hr, bw, hr, "F")
		if i%step == 0 {
			d.p.SetXY(cx-7, y+plotH+1)
			d.color(pdfMuted)
			d.p.CellFormat(14, 3, d.tr(t.Label), "", 0, "C", false, 0, "")
		}
	}
	ly := y + h + 1
	d.fill(pdfNew)
	d.p.Rect(x, ly, 3, 3, "F")
	d.p.SetXY(x+4, ly-1)
	d.p.Cell(12, 5, "New")
	d.fill(pdfFixed)
	d.p.Rect(x+18, ly, 3, 3, "F")
	d.p.SetXY(x+22, ly-1)
	d.p.Cell(12, 5, "Fixed")
}

// hbars draws labelled horizontal bars; each row is 6 mm tall.
func (d *pdfDoc) hbars(x, y, w float64, items []barItem) {
	if len(items) == 0 {
		d.p.SetXY(x, y)
		d.color(pdfMuted)
		d.p.SetFont("Helvetica", "I", 8)
		d.p.Cell(w, 5, "Nothing to show.")
		return
	}
	maxV := 1
	for _, it := range items {
		maxV = maxInt(maxV, it.Value)
	}
	labelW := 42.0
	for i, it := range items {
		yy := y + float64(i)*6
		d.p.SetXY(x, yy)
		d.color(pdfInk)
		d.p.SetFont("Helvetica", "", 7.5)
		d.p.Cell(labelW, 5, d.tr(ellipsize(it.Label, 28)))
		bw := (w - labelW - 8) * float64(it.Value) / float64(maxV)
		if bw < 0.8 {
			bw = 0.8
		}
		c := pdfSev["low"]
		if strings.HasPrefix(it.Class, "s-") {
			if sc, ok := pdfSev[strings.TrimPrefix(it.Class, "s-")]; ok {
				c = sc
			}
		}
		d.fill(c)
		d.p.Rect(x+labelW, yy+0.8, bw, 3.4, "F")
		d.p.SetXY(x+labelW+bw+1, yy)
		d.color(pdfMuted)
		d.p.Cell(8, 5, fmt.Sprint(it.Value))
	}
}

// ---------------------------------------------------------------- tables

// table draws a bordered table with a repeating header. Rows are never split across pages.
func (d *pdfDoc) table(cols []pdfCol, rows [][]pdfCell, size float64) {
	p := d.p
	lh := size/2.2 + 1.0
	header := func() {
		d.ensure(lh + 6)
		x, y := pdfMargin, p.GetY()
		d.fill(pdfNavy)
		d.stroke(pdfNavy)
		p.SetFont("Helvetica", "B", size)
		d.color(rgb{255, 255, 255})
		for _, c := range cols {
			p.SetXY(x, y)
			p.CellFormat(c.W, lh+1.6, d.tr(c.Title), "1", 0, c.Align, true, 0, "")
			x += c.W
		}
		p.SetY(y + lh + 1.6)
	}
	header()
	for ri, row := range rows {
		if ri >= rowCap {
			d.para(fmt.Sprintf("… %d more row(s) not shown. Export the CSV for the complete list.", len(rows)-rowCap), 8, pdfMuted)
			break
		}
		// height of the tallest cell
		maxLines := 1
		texts := make([][][]byte, len(cols))
		for i, c := range cols {
			if i >= len(row) {
				continue
			}
			style := ""
			if row[i].Bold {
				style = "B"
			}
			font := "Helvetica"
			if row[i].Mono {
				font = "Courier"
			}
			p.SetFont(font, style, size)
			texts[i] = p.SplitLines([]byte(d.tr(ellipsizeBytes(row[i].Text, 600))), c.W-2.4)
			maxLines = maxInt(maxLines, len(texts[i]))
		}
		h := float64(maxLines)*lh + 2
		if p.GetY()+h > pdfBottom {
			p.AddPage()
			header()
		}
		x, y := pdfMargin, p.GetY()
		d.stroke(pdfLine)
		if ri%2 == 1 {
			d.fill(rgb{248, 250, 252})
		} else {
			d.fill(rgb{255, 255, 255})
		}
		for i, c := range cols {
			p.Rect(x, y, c.W, h, "DF")
			if i < len(row) {
				style := ""
				if row[i].Bold {
					style = "B"
				}
				font := "Helvetica"
				if row[i].Mono {
					font = "Courier"
				}
				p.SetFont(font, style, size)
				if row[i].Color != nil {
					d.color(*row[i].Color)
				} else {
					d.color(pdfInk)
				}
				for li, ln := range texts[i] {
					p.SetXY(x+1.2, y+1+float64(li)*lh)
					p.CellFormat(c.W-2.4, lh, string(ln), "", 0, c.Align, false, 0, "")
				}
			}
			x += c.W
		}
		p.SetY(y + h)
	}
	p.Ln(3)
}

func ellipsizeBytes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func sevCell(sev string) pdfCell {
	c := pdfSev[strings.ToLower(sev)]
	return pdfCell{Text: strings.ToUpper(sev), Color: &c, Bold: true}
}

// ---------------------------------------------------------------- detail pages

func (d *pdfDoc) detail(rep *Report) {
	p := d.p
	d.heading("Detail for the security team", 16)
	if rep.Filter.Sev != nil {
		d.para("Severity filter applied to the sections below: "+rep.Filter.Label()+". The executive summary always covers every finding.", 9, pdfMuted)
	}

	d.heading("Domains", 13)
	var rows [][]pdfCell
	for _, t := range rep.Targets {
		state := "monitoring"
		if !t.Enabled {
			state = "paused"
		} else if !t.Baselined {
			state = "baselining"
		}
		rows = append(rows, []pdfCell{{Text: t.Domain, Bold: true}, {Text: state}, {Text: fmt.Sprint(t.Hosts)}, {Text: fmt.Sprint(t.NewHosts)},
			{Text: fmt.Sprint(t.OpenFindings["high"])}, {Text: fmt.Sprint(t.OpenFindings["medium"])}, {Text: fmt.Sprint(t.OpenFindings["low"])}, {Text: shortTS(t.LastScan)}})
	}
	d.table([]pdfCol{{"Domain", 42, "L"}, {"Status", 22, "L"}, {"Hosts", 14, "R"}, {"New", 12, "R"}, {"High", 13, "R"}, {"Medium", 16, "R"}, {"Low", 12, "R"}, {"Last scan", 49, "L"}}, rows, 8)

	d.heading(fmt.Sprintf("Open findings (%d)", len(rep.Findings)), 13)
	if len(rep.Findings) == 0 {
		d.para("Nothing to show.", 9, pdfMuted)
	} else {
		d.table([]pdfCol{{"Severity", 17, "L"}, {"Finding", 44, "L"}, {"Asset", 44, "L"}, {"Detail", 75, "L"}}, findingRows(rep.Findings, true), 7.5)
	}

	d.heading(fmt.Sprintf("New findings in the last %s (%d)", periodWords(rep.Days), len(rep.NewFindings)), 13)
	if len(rep.NewFindings) == 0 {
		d.para("No new findings in this period.", 9, pdfMuted)
	} else {
		var nr [][]pdfCell
		for _, f := range rep.NewFindings {
			now := "open"
			switch f.Status {
			case "ack":
				now = "accepted"
			case "resolved":
				now = "fixed already"
			}
			nr = append(nr, []pdfCell{sevCell(f.Severity), {Text: describeFinding(f).Title, Bold: true}, {Text: hostOrRoot(f)}, {Text: shortTS(f.FirstSeen)}, {Text: now}})
		}
		d.table([]pdfCol{{"Severity", 17, "L"}, {"Finding", 56, "L"}, {"Asset", 46, "L"}, {"First seen", 30, "L"}, {"Now", 31, "L"}}, nr, 7.5)
	}

	d.heading(fmt.Sprintf("Resolved findings in the last %s (%d)", periodWords(rep.Days), len(rep.ResolvedFindings)), 13)
	if len(rep.ResolvedFindings) == 0 {
		d.para("Nothing was resolved in this period.", 9, pdfMuted)
	} else {
		var rr [][]pdfCell
		for _, f := range rep.ResolvedFindings {
			rr = append(rr, []pdfCell{sevCell(f.Severity), {Text: describeFinding(f).Title, Bold: true}, {Text: hostOrRoot(f)}, {Text: shortTS(f.FirstSeen)}, {Text: shortTS(f.LastSeen)}})
		}
		d.table([]pdfCol{{"Severity", 17, "L"}, {"Finding", 56, "L"}, {"Asset", 47, "L"}, {"First seen", 30, "L"}, {"Fixed", 30, "L"}}, rr, 7.5)
	}

	// grouped by finding name
	p.AddPage()
	d.heading(fmt.Sprintf("Grouped by finding (%d type%s)", len(rep.ByFinding), plural(len(rep.ByFinding))), 13)
	if len(rep.ByFinding) == 0 {
		d.para("Nothing to show.", 9, pdfMuted)
	}
	for _, g := range rep.ByFinding {
		d.ensure(48)
		c := pdfSev[strings.ToLower(g.Severity)]
		y := p.GetY()
		d.fill(pdfPanel)
		d.stroke(pdfLine)
		p.Rect(pdfMargin, y, pdfWidth, 7, "DF")
		d.fill(c)
		p.Rect(pdfMargin, y, 2.2, 7, "F")
		p.SetXY(pdfMargin+4, y+1)
		d.color(pdfInk)
		p.SetFont("Helvetica", "B", 10)
		p.Cell(pdfWidth-60, 5, d.tr(ellipsize(g.Title, 70)))
		p.SetFont("Helvetica", "", 8)
		d.color(pdfMuted)
		p.CellFormat(55, 5, d.tr(fmt.Sprintf("%s · %d asset%s · %d finding%s", strings.ToUpper(g.Severity), g.Assets, plural(g.Assets), len(g.Items), plural(len(g.Items)))), "", 0, "R", false, 0, "")
		p.SetY(y + 9)
		d.labelled("Source", g.Info.Source)
		d.labelled("Risk", g.Info.Risk)
		d.labelled("Fix", g.Info.Solution)
		var ir [][]pdfCell
		for _, f := range g.Items {
			ir = append(ir, []pdfCell{sevCell(f.Severity), {Text: hostOrRoot(f), Mono: true}, {Text: f.Detail}})
		}
		d.table([]pdfCol{{"Severity", 17, "L"}, {"Asset", 56, "L"}, {"Detail", 107, "L"}}, ir, 7.5)
	}

	// grouped by asset
	p.AddPage()
	d.heading(fmt.Sprintf("Grouped by asset (%d)", len(rep.ByAsset)), 13)
	if len(rep.ByAsset) == 0 {
		d.para("Nothing to show.", 9, pdfMuted)
	}
	for i, g := range rep.ByAsset {
		if i >= rowCap/2 {
			d.para(fmt.Sprintf("… %d more asset(s) not shown. Export the findings CSV for the complete list.", len(rep.ByAsset)-i), 8, pdfMuted)
			break
		}
		d.ensure(26)
		c := pdfSev[strings.ToLower(g.Max)]
		y := p.GetY()
		d.fill(pdfPanel)
		d.stroke(pdfLine)
		p.Rect(pdfMargin, y, pdfWidth, 6.5, "DF")
		d.fill(c)
		p.Rect(pdfMargin, y, 2.2, 6.5, "F")
		p.SetXY(pdfMargin+4, y+0.9)
		d.color(pdfInk)
		p.SetFont("Courier", "B", 9)
		p.Cell(pdfWidth-50, 5, d.tr(ellipsize(g.Host, 60)))
		p.SetFont("Helvetica", "", 8)
		d.color(pdfMuted)
		p.CellFormat(45, 5, fmt.Sprintf("%d finding%s", len(g.Findings), plural(len(g.Findings))), "", 0, "R", false, 0, "")
		p.SetY(y + 7.5)
		var ar [][]pdfCell
		for _, f := range g.Findings {
			ar = append(ar, []pdfCell{sevCell(f.Severity), {Text: describeFinding(f).Title, Bold: true}, {Text: f.Detail}})
		}
		d.table([]pdfCol{{"Severity", 17, "L"}, {"Finding", 58, "L"}, {"Detail", 105, "L"}}, ar, 7.5)
	}

	// changes
	d.heading(fmt.Sprintf("Changes in the last %s (%d)", periodWords(rep.Days), len(rep.Changes)), 13)
	if len(rep.ChangeCounts) > 0 {
		var parts []string
		for _, k := range rep.ChangeCounts {
			parts = append(parts, fmt.Sprintf("%s %d", k.Kind, k.Count))
		}
		d.para(strings.Join(parts, "   ·   "), 8.5, pdfInk)
	}
	if len(rep.Changes) == 0 {
		d.para("No changes were detected in this period.", 9, pdfMuted)
	} else {
		var cr [][]pdfCell
		for i, e := range rep.Changes {
			if i >= 150 {
				break
			}
			cr = append(cr, []pdfCell{{Text: shortTS(e.TS)}, sevCell(e.Severity), {Text: e.Kind}, {Text: e.Host, Mono: true}, {Text: e.Detail}})
		}
		d.table([]pdfCol{{"When", 24, "L"}, {"Severity", 16, "L"}, {"Type", 26, "L"}, {"Host", 42, "L"}, {"Detail", 72, "L"}}, cr, 7)
		if len(rep.Changes) > 150 {
			d.para(fmt.Sprintf("Showing the newest 150 of %d changes. The Events page has the full list.", len(rep.Changes)), 8, pdfMuted)
		}
	}

	// inventory
	if len(rep.Inventory) > 0 {
		d.heading(fmt.Sprintf("Host inventory (%d host%s)", rep.InventoryTotal, plural(rep.InventoryTotal)), 13)
		var hr [][]pdfCell
		for i, h := range rep.Inventory {
			if i >= 200 {
				break
			}
			var addrs []string
			for _, a := range h.Addrs {
				s := a.IP
				if a.ASN != 0 {
					s += fmt.Sprintf(" (AS%d %s)", a.ASN, a.Org)
				}
				addrs = append(addrs, s)
			}
			hr = append(hr, []pdfCell{{Text: h.Host, Mono: true}, {Text: strings.Join(addrs, "; ")}, {Text: strings.Join(h.CNAMEs, ", ")}, {Text: shortTS(h.FirstSeen)}})
		}
		d.table([]pdfCol{{"Host", 56, "L"}, {"Addresses and owner", 66, "L"}, {"CNAME", 34, "L"}, {"First seen", 24, "L"}}, hr, 7)
		if rep.InventoryTotal > 200 {
			d.para(fmt.Sprintf("Showing 200 of %d hosts. Export the hosts CSV for the complete list.", rep.InventoryTotal), 8, pdfMuted)
		}
	}
}

func (d *pdfDoc) labelled(label, txt string) {
	p := d.p
	p.SetFont("Helvetica", "", 8.5)
	lines := p.SplitLines([]byte(d.tr(txt)), pdfWidth-18)
	d.ensure(float64(len(lines))*4 + 2)
	y := p.GetY()
	p.SetXY(pdfMargin, y)
	p.SetFont("Helvetica", "B", 8.5)
	d.color(pdfMuted)
	p.Cell(16, 4, label)
	p.SetXY(pdfMargin+18, y)
	p.SetFont("Helvetica", "", 8.5)
	d.color(pdfInk)
	p.MultiCell(pdfWidth-18, 4, d.tr(txt), "", "L", false)
	p.Ln(0.5)
}

func findingRows(fs []Finding, _ bool) [][]pdfCell {
	rows := make([][]pdfCell, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, []pdfCell{sevCell(f.Severity), {Text: describeFinding(f).Title, Bold: true}, {Text: hostOrRoot(f), Mono: true}, {Text: f.Detail}})
	}
	return rows
}

func shortTS(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04")
}
