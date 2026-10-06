package tui

import (
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/4rji/ctvault/internal/query"
)

// form is how the certificate view shows a certificate; f cycles through
// them.
type form int

const (
	formDetail form = iota // names, entries, chains and the linked certificate
	formText               // fetch's text dump
	formPEM
)

var formNames = []string{"detail", "text", "PEM"}

// certView is an open certificate.
type certView struct {
	id      uint64
	form    form
	full    bool // the detail's lookups were made
	c       *query.Cert
	names   []map[string]any
	entries []query.Entry
	chains  [][]uint64
	subject map[uint64]string // of the chains' certificates
	linked  *query.Cert
}

// openCert loads a certificate; for the detail form, also its names, its
// entries, its chains and the other half of its issuance.
func (m *Model) openCert(id uint64, f form) tea.Cmd {
	ctx, seq := m.begin("loading certificate")
	src := m.certs
	return func() tea.Msg {
		cv := &certView{id: id, form: f, full: f == formDetail}
		err := src.with(func(fe *query.Fetcher) error {
			c, err := fe.ByCertID(ctx, id)
			if err != nil {
				return err
			}
			cv.c = c
			if !cv.full {
				return nil
			}
			if cv.names, err = fe.Names(ctx, c); err != nil {
				return err
			}
			if cv.entries, err = fe.Entries(ctx, id); err != nil {
				return err
			}
			if cv.chains, err = fe.Chains(ctx, id); err != nil {
				return err
			}
			cv.subject = map[uint64]string{}
			for _, ch := range cv.chains {
				for _, cid := range ch {
					if _, ok := cv.subject[cid]; ok {
						continue
					}
					cc, err := fe.ByCertID(ctx, cid)
					if err != nil {
						return err
					}
					cv.subject[cid] = query.Render(cc.Row["subject_cn"])
				}
			}
			cv.linked, err = fe.Linked(ctx, c)
			return err
		})
		return certMsg{seq: seq, cv: cv, err: err}
	}
}

func (m *Model) certKey(k tea.KeyPressMsg) tea.Cmd {
	cv := m.cert
	switch k.String() {
	case "q":
		m.abort()
		return tea.Quit
	case "?":
		m.showHelp = true
		return nil
	case "esc":
		if m.busy != "" {
			m.cancelRunning()
		} else {
			m.cert = nil
		}
		return nil
	case "R":
		return m.repin()
	case "f":
		next := (cv.form + 1) % 3
		if next == formDetail && !cv.full {
			return m.openCert(cv.id, formDetail)
		}
		cv.form = next
		m.showCert()
		return nil
	case "w":
		ext := ".pem"
		if cv.form == formText {
			ext = ".txt"
		}
		m.ask(promptWrite, hex.EncodeToString(cv.c.SHA256[:])[:16]+ext)
		return nil
	}
	m.vp, _ = m.vp.Update(k)
	return nil
}

// showCert puts the certificate's current form in the viewport.
func (m *Model) showCert() {
	m.vp.SetContent(m.cert.content())
	m.vp.GotoTop()
}

// shown is what w writes: the PEM, or the text dump in the text form.
func (cv *certView) shown() []byte {
	if cv.form == formText {
		return []byte(query.Dump(cv.c))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cv.c.DER})
}

func (cv *certView) content() string {
	if cv.form != formDetail {
		return string(cv.shown())
	}
	c, r := cv.c, cv.c.Row
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-10s %s\n", k, v) }
	line("sha256", hex.EncodeToString(c.SHA256[:]))
	line("cert_id", fmt.Sprintf("%d (batch %s)", c.CertID, c.Batch))
	line("kind", query.Render(r["kind"]))
	line("parse", query.Render(r["parse_status"]))
	line("subject", query.Render(r["subject_cn"]))
	issuer := query.Render(r["issuer_cn"])
	if o := query.Render(r["issuer_o"]); o != "" {
		issuer += " (" + o + ")"
	}
	line("issuer", issuer)
	line("validity", query.Render(r["not_before"])+" → "+query.Render(r["not_after"]))
	key := strings.TrimSpace(query.Render(r["key_alg"]) + " " + query.Render(r["key_curve"]))
	if bits := query.Render(r["key_bits"]); bits != "" && bits != "0" {
		key += " (" + bits + " bits)"
	}
	line("key", key)
	linked := "none found"
	if l := cv.linked; l != nil {
		linked = fmt.Sprintf("%s %d · sha256 %s", query.Render(l.Row["kind"]), l.CertID, hex.EncodeToString(l.SHA256[:]))
	}
	line("linked", linked)

	fmt.Fprintf(&b, "\nnames (%d)\n", len(cv.names))
	for _, n := range cv.names {
		fmt.Fprintf(&b, "  %-8s %s\n", query.Render(n["source"]), query.Render(n["name"]))
	}
	fmt.Fprintf(&b, "\nentries (%d)\n", len(cv.entries))
	for _, e := range cv.entries {
		fmt.Fprintf(&b, "  %s #%d  %s  %s\n", e.Log, e.Idx, query.Render(e.CTTime), e.EntryType)
	}
	fmt.Fprintf(&b, "\nchains (%d)\n", len(cv.chains))
	for i, ch := range cv.chains {
		parts := make([]string, len(ch))
		for j, id := range ch {
			parts[j] = fmt.Sprintf("%d %s", id, cv.subject[id])
		}
		fmt.Fprintf(&b, "  %d. %s\n", i+1, strings.Join(parts, " → "))
	}
	return b.String()
}

// write is w: the shown certificate to a new file. It never overwrites.
func (m *Model) write(path string) {
	path = expand(strings.TrimSpace(path))
	if err := writeNew(path, m.cert.shown()); err != nil {
		m.fail(err)
		return
	}
	m.note("wrote " + path)
}

// writeNew creates path with data and fails if it exists.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s exists: choose another name", path)
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// expand resolves a leading ~/ to the home directory.
func expand(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}
