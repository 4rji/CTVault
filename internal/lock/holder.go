package lock

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// procLocks lists the kernel's file locks (tests replace it).
var procLocks = "/proc/locks"

// Holder reports whether a process holds the writer lock at path, and its
// PID, from /proc/locks. Unlike Acquire it takes no lock and writes
// nothing, so a reader such as verify can tell whether a writer runs
// (amendment A5 §1). The PID is 0 when the holder is in another PID
// namespace.
func Holder(path string) (pid int, held bool, err error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	dev := fmt.Sprintf("%02x:%02x:%d", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
	f, err := os.Open(procLocks)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "9: FLOCK  ADVISORY  WRITE 599271 08:01:698941 0 EOF"; a blocked
		// waiter's line starts "9: -> FLOCK ...".
		fs := strings.Fields(sc.Text())
		if len(fs) < 6 || fs[1] != "FLOCK" || fs[3] != "WRITE" || fs[5] != dev {
			continue
		}
		pid, _ := strconv.Atoi(fs[4])
		return pid, true, nil
	}
	return 0, false, sc.Err()
}
