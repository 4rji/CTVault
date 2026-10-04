package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestOf(t *testing.T) {
	base := errors.New("boom")
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, OK},
		{"plain", base, Error},
		{"coded", With(DiskCap, base), DiskCap},
		{"wrapped coded", fmt.Errorf("context: %w", With(Volume, base)), Volume},
		{"formatted", Withf(Verification, "bad %d", 1), Verification},
	}
	for _, c := range cases {
		if got := Of(c.err); got != c.want {
			t.Errorf("%s: Of() = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestWithNilStaysNil(t *testing.T) {
	if With(Usage, nil) != nil {
		t.Fatal("With(code, nil) must return nil")
	}
}

func TestCodedErrorUnwraps(t *testing.T) {
	base := errors.New("root cause")
	if !errors.Is(With(Error, base), base) {
		t.Fatal("errors.Is must see through CodedError")
	}
}
