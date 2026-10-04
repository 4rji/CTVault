package leaf

import (
	"bytes"
	"crypto/sha256"
)

// findIssuer picks c's issuer among chain by relationship, never by position.
// Candidates that share a key and signing role (a cross-signed copy of the
// same CA) count as one.
func findIssuer(c *cert, chain []*cert) (*cert, Code) {
	var found *cert
	for _, cand := range chain {
		if cand == nil || !c.issuedBy(cand) {
			continue
		}
		if found != nil && (!bytes.Equal(found.spki, cand.spki) || found.ctSigner != cand.ctSigner) {
			return nil, ChainIssuerAmbiguous
		}
		if found == nil {
			found = cand
		}
	}
	if found == nil {
		return nil, ChainIssuerMissing
	}
	return found, OK
}

// checkPrecert identifies the final issuer and cross-checks the log's
// issuer_key_hash and TBS against the precertificate (RFC 6962 §3.1-3.2).
// Failures are recorded; the decoded fields stay as logged.
func (e *Entry) checkPrecert() {
	pre, err := parseCert(e.CertDER)
	if err != nil {
		e.fail(PrecertTBSMismatch)
		return
	}
	chain := make([]*cert, len(e.Chain))
	for i, der := range e.Chain {
		chain[i], _ = parseCert(der) // unparseable chain certs are never candidates
	}
	issuer, code := findIssuer(pre, chain)
	if code != OK {
		e.fail(code)
		return
	}
	rw := rewrite{drop: oidPoison}
	final := issuer
	if issuer.ctSigner {
		// A Precertificate Signing Certificate: the real issuer is the CA that
		// certified it, and the log's TBS carries that CA's name and key ID.
		if final, code = findIssuer(issuer, chain); code != OK {
			e.fail(code)
			return
		}
		rw.issuer = issuer.issuer
		if pre.hasExtension(oidAKI) {
			if issuer.akid == nil {
				e.fail(PrecertTBSMismatch)
				return
			}
			rw.akid = issuer.akid
		}
	}
	if sha256.Sum256(final.spki) != e.IssuerKeyHash {
		e.fail(IssuerKeyHashMismatch)
		return
	}
	tbs, err := pre.rebuildTBS(rw)
	if err != nil || !bytes.Equal(tbs, e.PrecertTBS) {
		e.fail(PrecertTBSMismatch)
	}
}
