package volume

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MountEntry is one line of /proc/self/mountinfo, as documented in proc(5).
type MountEntry struct {
	MountID      int
	MajorMinor   string // "8:1"
	Root         string
	MountPoint   string // octal escapes decoded
	MountOptions []string
	FSType       string
	Source       string
	SuperOptions []string
}

// ParseMountInfo parses the mountinfo format.
func ParseMountInfo(r io.Reader) ([]MountEntry, error) {
	var out []MountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		f := strings.Fields(text)
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(f) < sep+4 {
			return nil, fmt.Errorf("mountinfo line %d: malformed: %q", line, text)
		}
		id, err := strconv.Atoi(f[0])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: bad mount id %q", line, f[0])
		}
		out = append(out, MountEntry{
			MountID:      id,
			MajorMinor:   f[2],
			Root:         unescape(f[3]),
			MountPoint:   unescape(f[4]),
			MountOptions: strings.Split(f[5], ","),
			FSType:       f[sep+1],
			Source:       unescape(f[sep+2]),
			SuperOptions: strings.Split(f[sep+3], ","),
		})
	}
	return out, sc.Err()
}

// unescape decodes the \NNN octal escapes the kernel writes for space, tab,
// newline and backslash in mountinfo paths.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// MountFor returns the mount that contains absPath: the entry with the longest
// matching mount point, preferring the later (topmost) one on ties.
func MountFor(entries []MountEntry, absPath string) (MountEntry, bool) {
	best := -1
	for i, e := range entries {
		if !within(absPath, e.MountPoint) {
			continue
		}
		if best < 0 || len(e.MountPoint) >= len(entries[best].MountPoint) {
			best = i
		}
	}
	if best < 0 {
		return MountEntry{}, false
	}
	return entries[best], true
}

func within(path, mountPoint string) bool {
	if mountPoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}
