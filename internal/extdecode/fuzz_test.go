package extdecode

import (
	"reflect"
	"testing"
)

// FuzzDecoders: no input panics a decoder, and each answers the same twice.
func FuzzDecoders(f *testing.F) {
	f.Add(uint8(0), []byte{0x30, 0x00})
	f.Add(uint8(6), sctList(sctBytes(1, 2, nil, []byte{3})))
	f.Add(uint8(3), []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, which uint8, v []byte) {
		run := func() any {
			switch which % 7 {
			case 0:
				r, c := Policies(v)
				return []any{r, c}
			case 1:
				r, c := EKUs(v)
				return []any{r, c}
			case 2:
				r, c := KeyUsage(v)
				return []any{r, c}
			case 3:
				r, c := BasicConstraints(v)
				return []any{r, c}
			case 4:
				r, c := AIA(v)
				return []any{r, c}
			case 5:
				r, c := CRLDPs(v)
				return []any{r, c}
			}
			r, c := SCTs(v)
			return []any{r, c}
		}
		if a, b := run(), run(); !reflect.DeepEqual(a, b) {
			t.Fatalf("two answers: %v and %v", a, b)
		}
	})
}
