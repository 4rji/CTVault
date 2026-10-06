package query

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Render is how every text format shows a value: times in RFC 3339 UTC,
// lists joined by ", ", NULL as empty.
func Render(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Render(e)
		}
		return strings.Join(parts, ", ")
	case []byte:
		return fmt.Sprintf("%x", x)
	}
	return fmt.Sprint(v)
}

// jsonOf is a value as JSON: times as RFC 3339 strings, lists as arrays.
func jsonOf(v any) any {
	switch x := v.(type) {
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonOf(e)
		}
		return out
	case []byte:
		return fmt.Sprintf("%x", x)
	}
	return v
}

// RowWriter writes rows in one format, one at a time: table, md, csv, or
// json (the objects of a JSON array, without the brackets).
type RowWriter interface {
	Header(cols []string) error
	Row(vals []any) error
	End() error
}

// NewRowWriter returns the writer for format.
func NewRowWriter(format string, w io.Writer) RowWriter {
	switch format {
	case "md":
		return &mdWriter{w: w}
	case "csv":
		return &csvWriter{w: csv.NewWriter(w)}
	case "json":
		return &jsonWriter{w: w}
	}
	return &tableWriter{w: w}
}

// tableWriter buffers its rows to align the columns: terminal tables are
// limited to 100 rows by default (amendment A3 §3.3).
type tableWriter struct {
	w    io.Writer
	cols []string
	rows [][]string
}

func (t *tableWriter) Header(cols []string) error { t.cols = cols; return nil }
func (t *tableWriter) Row(vals []any) error {
	r := make([]string, len(vals))
	for i, v := range vals {
		r[i] = Render(v)
	}
	t.rows = append(t.rows, r)
	return nil
}
func (t *tableWriter) End() error {
	width := make([]int, len(t.cols))
	for i, c := range t.cols {
		width[i] = len(c)
	}
	for _, r := range t.rows {
		for i, v := range r {
			width[i] = max(width[i], len([]rune(v)))
		}
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			if i < len(cells)-1 {
				fmt.Fprintf(&b, "%-*s", width[i], c)
			} else {
				b.WriteString(c)
			}
		}
		fmt.Fprintln(t.w, strings.TrimRight(b.String(), " "))
	}
	head := make([]string, len(t.cols))
	for i, c := range t.cols {
		head[i] = strings.ToUpper(c)
	}
	line(head)
	for _, r := range t.rows {
		line(r)
	}
	return nil
}

type mdWriter struct{ w io.Writer }

func mdCell(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }

func (m *mdWriter) Header(cols []string) error {
	_, err := fmt.Fprintf(m.w, "| %s |\n|%s|\n", strings.Join(cols, " | "), strings.Repeat("---|", len(cols)))
	return err
}
func (m *mdWriter) Row(vals []any) error {
	cells := make([]string, len(vals))
	for i, v := range vals {
		cells[i] = mdCell(Render(v))
	}
	_, err := fmt.Fprintf(m.w, "| %s |\n", strings.Join(cells, " | "))
	return err
}
func (m *mdWriter) End() error { return nil }

type csvWriter struct{ w *csv.Writer }

func (c *csvWriter) Header(cols []string) error { return c.w.Write(cols) }
func (c *csvWriter) Row(vals []any) error {
	r := make([]string, len(vals))
	for i, v := range vals {
		r[i] = Render(v)
	}
	return c.w.Write(r)
}
func (c *csvWriter) End() error { c.w.Flush(); return c.w.Error() }

// jsonWriter writes the rows of a JSON array, one object per row with the
// columns in order.
type jsonWriter struct {
	w    io.Writer
	cols []string
	n    int
}

func (j *jsonWriter) Header(cols []string) error { j.cols = cols; return nil }
func (j *jsonWriter) Row(vals []any) error {
	var b strings.Builder
	if j.n > 0 {
		b.WriteString(",\n")
	}
	b.WriteString("  {")
	for i, c := range j.cols {
		if i > 0 {
			b.WriteString(", ")
		}
		k, _ := json.Marshal(c)
		v, err := json.Marshal(jsonOf(vals[i]))
		if err != nil {
			return err
		}
		b.Write(k)
		b.WriteString(": ")
		b.Write(v)
	}
	b.WriteString("}")
	j.n++
	_, err := io.WriteString(j.w, b.String())
	return err
}
func (j *jsonWriter) End() error { return nil }
