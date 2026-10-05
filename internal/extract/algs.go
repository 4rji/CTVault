package extract

// signatureAlgorithms names signature AlgorithmIdentifier OIDs (RFC 3279,
// 4055, 5758, 8410). An unknown OID is reported in dotted form.
var signatureAlgorithms = map[string]string{
	"1.2.840.113549.1.1.2":   "md2WithRSAEncryption",
	"1.2.840.113549.1.1.4":   "md5WithRSAEncryption",
	"1.2.840.113549.1.1.5":   "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.10":  "rsassaPss",
	"1.2.840.113549.1.1.11":  "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12":  "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13":  "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.14":  "sha224WithRSAEncryption",
	"1.2.840.10045.4.1":      "ecdsa-with-SHA1",
	"1.2.840.10045.4.3.1":    "ecdsa-with-SHA224",
	"1.2.840.10045.4.3.2":    "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3":    "ecdsa-with-SHA384",
	"1.2.840.10045.4.3.4":    "ecdsa-with-SHA512",
	"1.2.840.10040.4.3":      "dsa-with-SHA1",
	"2.16.840.1.101.3.4.3.1": "dsa-with-SHA224",
	"2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
	"1.3.101.112":            "Ed25519",
	"1.3.101.113":            "Ed448",
}

// Public key algorithm OIDs.
const (
	oidRSA     = "1.2.840.113549.1.1.1"
	oidRSAPSS  = "1.2.840.113549.1.1.10"
	oidEC      = "1.2.840.10045.2.1"
	oidEd25519 = "1.3.101.112"
	oidEd448   = "1.3.101.113"
	oidDSA     = "1.2.840.10040.4.1"
)

// namedCurves maps namedCurve OIDs to their names and sizes in bits.
var namedCurves = map[string]struct {
	name string
	bits int
}{
	"1.2.840.10045.3.1.1": {"P-192", 192},
	"1.3.132.0.33":        {"P-224", 224},
	"1.2.840.10045.3.1.7": {"P-256", 256},
	"1.3.132.0.34":        {"P-384", 384},
	"1.3.132.0.35":        {"P-521", 521},
	"1.3.132.0.10":        {"secp256k1", 256},
}
