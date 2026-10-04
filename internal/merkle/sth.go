package merkle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// SignedTreeHead is an RFC 6962 signed tree head with its raw DigitallySigned bytes.
type SignedTreeHead struct {
	TreeSize  uint64
	Timestamp uint64 // milliseconds since the Unix epoch
	RootHash  [32]byte
	Signature []byte // TLS DigitallySigned: hash alg (1) | sig alg (1) | uint16 len | sig
}

const (
	hashAlgSHA256 = 4
	sigAlgRSA     = 1
	sigAlgECDSA   = 3
)

// ErrBadSignature is returned when an STH signature does not verify.
var ErrBadSignature = errors.New("merkle: tree head signature does not verify")

// treeHeadSignatureInput builds the RFC 6962 §3.5 TreeHeadSignature structure.
func treeHeadSignatureInput(sth SignedTreeHead) []byte {
	b := make([]byte, 0, 2+8+8+32)
	b = append(b, 0 /* v1 */, 1 /* tree_hash */)
	b = binary.BigEndian.AppendUint64(b, sth.Timestamp)
	b = binary.BigEndian.AppendUint64(b, sth.TreeSize)
	return append(b, sth.RootHash[:]...)
}

// VerifySTH checks the STH signature with the log's public key (ECDSA P-256 or RSA, SHA-256).
func VerifySTH(pub crypto.PublicKey, sth SignedTreeHead) error {
	ds := sth.Signature
	if len(ds) < 4 {
		return fmt.Errorf("%w: DigitallySigned too short (%d bytes)", ErrBadSignature, len(ds))
	}
	hashAlg, sigAlg := ds[0], ds[1]
	n := int(binary.BigEndian.Uint16(ds[2:4]))
	if len(ds) != 4+n {
		return fmt.Errorf("%w: signature length %d does not match %d remaining bytes", ErrBadSignature, n, len(ds)-4)
	}
	if hashAlg != hashAlgSHA256 {
		return fmt.Errorf("%w: unsupported hash algorithm %d", ErrBadSignature, hashAlg)
	}
	sig := ds[4:]
	digest := sha256.Sum256(treeHeadSignatureInput(sth))
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if sigAlg != sigAlgECDSA || !ecdsa.VerifyASN1(k, digest[:], sig) {
			return ErrBadSignature
		}
	case *rsa.PublicKey:
		if sigAlg != sigAlgRSA || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return ErrBadSignature
		}
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrBadSignature, pub)
	}
	return nil
}
