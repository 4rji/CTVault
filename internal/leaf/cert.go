package leaf

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidPoison         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidSCTList        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidPrecertSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	oidSKI            = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI            = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidEKU            = asn1.ObjectIdentifier{2, 5, 29, 37}
)

var errCert = errors.New("leaf: malformed certificate")

var tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()

// extension is one X.509 extension, with its exact encoding.
type extension struct {
	oid      asn1.ObjectIdentifier
	critical bool
	value    []byte // extnValue contents
	raw      []byte // the whole Extension element
}

// cert holds the raw pieces of a certificate that the precert checks need.
// It is deliberately minimal: the full field extractor arrives in Plan 3.
type cert struct {
	tbsParts  [][]byte // every TBSCertificate child element, in order
	issuerAt  int      // index of issuer in tbsParts
	extAt     int      // index of the [3] extensions element, or -1
	issuer    []byte   // full Name element
	subject   []byte   // full Name element
	spki      []byte   // full SubjectPublicKeyInfo element
	exts      []extension
	ski, akid []byte // subject key ID; authority key ID's keyIdentifier
	ctSigner  bool   // has the RFC 6962 precertificate-signing EKU
}

// parseCert reads a DER certificate.
func parseCert(der []byte) (*cert, error) {
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() || !body.ReadASN1Element(&tbs, cbasn1.SEQUENCE) {
		return nil, errCert
	}
	return parseTBS(tbs)
}

func parseTBS(full []byte) (*cert, error) {
	s := cryptobyte.String(full)
	var tbs cryptobyte.String
	if !s.ReadASN1(&tbs, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, errCert
	}
	c := &cert{extAt: -1}
	var tags []cbasn1.Tag
	for !tbs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			return nil, errCert
		}
		c.tbsParts = append(c.tbsParts, el)
		tags = append(tags, tag)
	}
	i := 0
	if len(tags) > 0 && tags[0] == cbasn1.Tag(0).Constructed().ContextSpecific() {
		i = 1 // explicit version
	}
	// serial, signature, issuer, validity, subject, subjectPublicKeyInfo
	if len(tags) < i+6 || tags[i] != cbasn1.INTEGER || tags[i+2] != cbasn1.SEQUENCE ||
		tags[i+4] != cbasn1.SEQUENCE || tags[i+5] != cbasn1.SEQUENCE {
		return nil, errCert
	}
	c.issuerAt = i + 2
	c.issuer, c.subject, c.spki = c.tbsParts[i+2], c.tbsParts[i+4], c.tbsParts[i+5]
	for j := i + 6; j < len(tags); j++ {
		if tags[j] != tagExtensions {
			continue
		}
		if c.extAt >= 0 {
			return nil, errCert
		}
		c.extAt = j
		if err := c.parseExtensions(c.tbsParts[j]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *cert) parseExtensions(el []byte) error {
	s := cryptobyte.String(el)
	var wrapped, list cryptobyte.String
	if !s.ReadASN1(&wrapped, tagExtensions) || !wrapped.ReadASN1(&list, cbasn1.SEQUENCE) || !wrapped.Empty() {
		return errCert
	}
	for !list.Empty() {
		var raw, ext cryptobyte.String
		if !list.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
			return errCert
		}
		ext = raw
		var body cryptobyte.String
		var x extension
		var value cryptobyte.String
		if !ext.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&x.oid) {
			return errCert
		}
		// critical is a plain BOOLEAN DEFAULT FALSE. (cryptobyte's
		// ReadOptionalASN1Boolean is for explicitly tagged booleans.)
		if body.PeekASN1Tag(cbasn1.BOOLEAN) && !body.ReadASN1Boolean(&x.critical) {
			return errCert
		}
		if !body.ReadASN1(&value, cbasn1.OCTET_STRING) || !body.Empty() {
			return errCert
		}
		x.value, x.raw = value, raw
		c.exts = append(c.exts, x)
		switch {
		case x.oid.Equal(oidSKI):
			v := cryptobyte.String(x.value)
			var id cryptobyte.String
			if v.ReadASN1(&id, cbasn1.OCTET_STRING) && v.Empty() {
				c.ski = id
			}
		case x.oid.Equal(oidAKI):
			v := cryptobyte.String(x.value)
			var seq, id cryptobyte.String
			var present bool
			if v.ReadASN1(&seq, cbasn1.SEQUENCE) &&
				seq.ReadOptionalASN1(&id, &present, cbasn1.Tag(0).ContextSpecific()) && present {
				c.akid = id
			}
		case x.oid.Equal(oidEKU):
			v := cryptobyte.String(x.value)
			var seq cryptobyte.String
			if v.ReadASN1(&seq, cbasn1.SEQUENCE) {
				for !seq.Empty() {
					var oid asn1.ObjectIdentifier
					if !seq.ReadASN1ObjectIdentifier(&oid) {
						break
					}
					if oid.Equal(oidPrecertSigning) {
						c.ctSigner = true
					}
				}
			}
		}
	}
	return nil
}

// rewrite describes an RFC 6962 §3.2 TBS transformation.
type rewrite struct {
	drop   asn1.ObjectIdentifier // extension to remove
	issuer []byte                // replacement issuer Name element, if non-nil
	akid   []byte                // replacement AKI keyIdentifier, if non-nil
}

// rebuildTBS re-encodes the TBSCertificate with rw applied. Every element it
// does not change is copied byte for byte. If no extension remains, the [3]
// element is omitted, as RFC 6962 implementations do.
func (c *cert) rebuildTBS(rw rewrite) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for j, part := range c.tbsParts {
			switch {
			case j == c.issuerAt && rw.issuer != nil:
				b.AddBytes(rw.issuer)
			case j == c.extAt:
				var kept []extension
				for _, x := range c.exts {
					if !x.oid.Equal(rw.drop) {
						kept = append(kept, x)
					}
				}
				if len(kept) == 0 {
					continue
				}
				b.AddASN1(tagExtensions, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						for _, x := range kept {
							if rw.akid == nil || !x.oid.Equal(oidAKI) {
								b.AddBytes(x.raw)
								continue
							}
							addAKI(b, x.critical, rw.akid)
						}
					})
				})
			default:
				b.AddBytes(part)
			}
		}
	})
	return b.Bytes()
}

// addAKI encodes an AuthorityKeyIdentifier extension holding only keyid.
func addAKI(b *cryptobyte.Builder, critical bool, keyid []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidAKI)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes(keyid)
				})
			})
		})
	})
}

// hasExtension reports whether the certificate carries oid.
func (c *cert) hasExtension(oid asn1.ObjectIdentifier) bool {
	for _, x := range c.exts {
		if x.oid.Equal(oid) {
			return true
		}
	}
	return false
}

// issuedBy reports whether candidate can be c's issuer: its subject equals
// c's issuer name, and its subject key ID equals c's authority key ID when
// both are present.
func (c *cert) issuedBy(candidate *cert) bool {
	if !bytes.Equal(candidate.subject, c.issuer) {
		return false
	}
	return c.akid == nil || candidate.ski == nil || bytes.Equal(c.akid, candidate.ski)
}
