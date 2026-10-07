//go:build powerloss

package powerloss

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
)

var (
	baseDir = flag.String("powerloss.dir", "/mnt/disk/ctvault/powerloss", "where the run's files go")
	every   = flag.Int("powerloss.every", 1, "check every Nth crash point (1: every one)")
)

// imageSize is the filesystem's size (amendment A5 §13).
const imageSize = 64 << 20

type phaseCount struct {
	Flush, FUA, Checked, Skipped int
}

type failure struct {
	Point int    `json:"point"`
	Entry uint64 `json:"entry"`
	Phase string `json:"phase"`
	Error string `json:"error"`
}

// report is report.json (amendment A5 §15).
type report struct {
	Kernel       string                 `json:"kernel"`
	Started      time.Time              `json:"started"`
	Duration     string                 `json:"duration"`
	Mkfs         string                 `json:"mkfs"`
	MountOptions string                 `json:"mount_options"`
	LogEntries   uint64                 `json:"log_entries"`
	SectorSize   int                    `json:"sector_size"`
	Every        int                    `json:"every"`
	Order        []string               `json:"phase_order"`
	Phases       map[string]*phaseCount `json:"phases"`
	Points       int                    `json:"crash_points"`
	Checked      int                    `json:"checked"`
	SelfCheck    string                 `json:"self_check"`
	FinalCheck   string                 `json:"final_check"`
	Committed    []string               `json:"committed"`
	Failures     []failure              `json:"failures"`
	Pass         bool                   `json:"pass"`
}

// runner owns the run's devices, so that every exit releases them.
type runner struct {
	t      *testing.T
	base   string
	dir    string
	name   string
	rep    report
	points *os.File

	mu     sync.Mutex
	loops  []string
	mounts []string
	dmUp   bool
}

func (r *runner) run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (r *runner) loopDevices() ([]loopDevice, error) {
	out, err := r.run("losetup", "--json", "--list")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	return parseLosetup([]byte(out))
}

// attach attaches a loop device to file and checks that it is a /dev/loopN
// backed by exactly that file before anything uses it.
func (r *runner) attach(file string) (string, error) {
	out, err := r.run("losetup", "--find", "--show", file)
	if err != nil {
		return "", err
	}
	dev := strings.TrimSpace(out)
	devs, err := r.loopDevices()
	if err == nil {
		err = checkLoop(devs, dev, file)
	}
	if err != nil {
		return "", err // a device that fails the check is never touched again, not even detached
	}
	r.mu.Lock()
	r.loops = append(r.loops, dev)
	r.mu.Unlock()
	return dev, nil
}

func (r *runner) detach(dev string) error {
	_, err := r.run("losetup", "-d", dev)
	r.mu.Lock()
	r.loops = slices.DeleteFunc(r.loops, func(d string) bool { return d == dev })
	r.mu.Unlock()
	return err
}

func (r *runner) mount(dev, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, err := r.run("mount", "-t", "ext4", dev, dir); err != nil {
		return err
	}
	r.mu.Lock()
	r.mounts = append(r.mounts, dir)
	r.mu.Unlock()
	return nil
}

func (r *runner) umount(dir string) error {
	var err error
	for i := 0; i < 20; i++ { // a closing DuckDB may hold the folder for a moment
		if _, err = r.run("umount", dir); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.mu.Lock()
	r.mounts = slices.DeleteFunc(r.mounts, func(d string) bool { return d == dir })
	r.mu.Unlock()
	return err
}

// cleanup releases whatever the run still holds, newest first.
func (r *runner) cleanup() {
	r.mu.Lock()
	mounts, loops, dmUp := slices.Clone(r.mounts), slices.Clone(r.loops), r.dmUp
	r.mu.Unlock()
	for i := len(mounts) - 1; i >= 0; i-- {
		if err := r.umount(mounts[i]); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
		}
	}
	if dmUp {
		if _, err := r.run("dmsetup", "remove", r.name); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
		}
		r.mu.Lock()
		r.dmUp = false
		r.mu.Unlock()
	}
	for i := len(loops) - 1; i >= 0; i-- {
		if err := r.detach(loops[i]); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
		}
	}
}

func (r *runner) phase(name string) *phaseCount {
	if name == "" {
		name = "setup"
	}
	if r.rep.Phases[name] == nil {
		r.rep.Phases[name] = &phaseCount{}
		r.rep.Order = append(r.rep.Order, name)
	}
	return r.rep.Phases[name]
}

// finish writes the report beside the run and as the latest, and gives the
// files back to the user who ran sudo.
func (r *runner) finish() {
	r.rep.Duration = time.Since(r.rep.Started).Round(time.Second).String()
	b, _ := json.MarshalIndent(r.rep, "", "  ")
	for _, p := range []string{filepath.Join(r.dir, "report.json"), filepath.Join(r.base, "report.json")} {
		if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
		}
	}
	if r.points != nil {
		r.points.Close()
	}
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr == nil && gerr == nil {
		filepath.Walk(r.base, func(p string, _ os.FileInfo, err error) error {
			if err == nil {
				os.Lchown(p, uid, gid)
			}
			return nil
		})
	}
	fmt.Printf("report: %s (pass: %v)\n", filepath.Join(r.base, "report.json"), r.rep.Pass)
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close() // loop devices read through the page cache: no fsync needed
}

func fileSum(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// useRegistry makes recovery at a point run as the binary that was running
// then: v1 through the ingest phase, the test v2 from the upgrade on.
func useRegistry(phase string) {
	switch phase {
	case "setup", "ingest":
		derive.SetRegistry([]derive.Versions{{Current: derive.Certs{}}, {Current: derive.Names{}}})
	default:
		derive.SetRegistry(derivetest.Registries["v2"])
	}
}

// checkImage checks one crash point: a copy of the image, mounted read-write
// (ext4 replays its journal as on a reboot), then Inspect and the checks
// across points.
func (r *runner) checkImage(ctx context.Context, img, phase string, tr *Tracker) error {
	chk := filepath.Join(r.dir, "check.img")
	if err := copyFile(img, chk); err != nil {
		return err
	}
	dev, err := r.attach(chk)
	if err != nil {
		return err
	}
	defer r.detach(dev)
	mnt := filepath.Join(r.dir, "chk")
	if err := r.mount(dev, mnt); err != nil {
		return fmt.Errorf("mounting the point's image: %w", err)
	}
	defer r.umount(mnt)
	useRegistry(phase)
	p, err := Inspect(ctx, WriterOptions(filepath.Join(mnt, "vault-root")))
	if err != nil {
		return err
	}
	return tr.Compare(p)
}

// TestPowerLoss is the power-loss gate (spec §13.6, amendment A5 Part 6C).
// It runs only as root: build it with -tags powerloss and run the binary
// with sudo.
func TestPowerLoss(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: build with -tags powerloss and run the binary with sudo (amendment A5 §13)")
	}
	ctx := context.Background()
	base, err := filepath.Abs(*baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{t: t, base: base, name: dmName(os.Getpid()),
		rep: report{Started: time.Now().UTC(), Every: *every, Phases: map[string]*phaseCount{}}}
	r.rep.Kernel = strings.TrimSpace(func() string {
		var u unix.Utsname
		unix.Uname(&u)
		return string(bytes.TrimRight(u.Release[:], "\x00"))
	}())

	// An earlier run's leftovers are reported, never removed.
	dmls, _ := r.run("dmsetup", "ls")
	devs, err := r.loopDevices()
	if err != nil {
		t.Fatal(err)
	}
	if lo := leftovers(dmls, devs, base); len(lo) > 0 {
		t.Fatalf("an earlier run left %s: remove them first (umount, dmsetup remove, losetup -d); nothing was changed", strings.Join(lo, ", "))
	}
	r.dir = filepath.Join(base, fmt.Sprintf("run-%d", time.Now().Unix()))
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer r.finish()
	defer r.cleanup()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "interrupted: releasing the run's devices")
		r.cleanup()
		r.finish()
		os.Exit(130)
	}()
	if r.points, err = os.Create(filepath.Join(r.dir, "points.log")); err != nil {
		t.Fatal(err)
	}

	// The device, its starting image, and the log.
	data, logf, start := filepath.Join(r.dir, "data.img"), filepath.Join(r.dir, "log.img"), filepath.Join(r.dir, "start.img")
	for p, size := range map[string]int64{data: imageSize, logf: 2 << 30} {
		f, err := os.Create(p)
		if err == nil {
			err = f.Truncate(size)
			f.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	r.rep.Mkfs = "mkfs.ext4 -q -F " + data
	if _, err := r.run("mkfs.ext4", "-q", "-F", data); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(data, start); err != nil {
		t.Fatal(err)
	}
	dataDev, err := r.attach(data)
	if err != nil {
		t.Fatal(err)
	}
	logDev, err := r.attach(logf)
	if err != nil {
		t.Fatal(err)
	}
	r.run("modprobe", "dm-log-writes") // built in, or already loaded, is fine
	if _, err := r.run("dmsetup", "create", r.name, "--table", fmt.Sprintf("0 %d log-writes %s %s", imageSize/512, dataDev, logDev)); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.dmUp = true
	r.mu.Unlock()
	mnt := filepath.Join(r.dir, "mnt")
	if err := r.mount("/dev/mapper/"+r.name, mnt); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile("/proc/self/mounts"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 4 && f[1] == mnt {
				r.rep.MountOptions = f[3]
			}
		}
	}

	// The workload, recorded (amendment A5 §14).
	fmt.Println("recording the workload")
	res, err := Workload(t, filepath.Join(mnt, "vault-root"), func(phase string) error {
		fmt.Println("phase", phase)
		_, err := r.run("dmsetup", "message", r.name, "0", "mark", phase)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r.rep.Committed = res.Committed
	unix.Sync()
	if err := r.umount(mnt); err != nil {
		t.Fatal(err)
	}
	if _, err := r.run("dmsetup", "remove", r.name); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.dmUp = false
	r.mu.Unlock()
	for _, d := range []string{dataDev, logDev} {
		if err := r.detach(d); err != nil {
			t.Fatal(err)
		}
	}

	// The replay and the checks (amendment A5 §15).
	work := filepath.Join(r.dir, "work.img")
	if err := copyFile(start, work); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLog(logf)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r.rep.LogEntries, r.rep.SectorSize = l.Entries, l.SectorSize
	rp, err := NewReplayer(work)
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()
	fmt.Printf("replaying %d log entries\n", l.Entries)
	var tr Tracker
	err = l.Each(func(e Entry) error {
		if err := rp.Apply(e); err != nil {
			return err
		}
		if e.IsMark() {
			r.phase(e.Mark)
		}
		if !e.CrashPoint() {
			return nil
		}
		pc := r.phase(e.Phase)
		if e.Flags&flagFlush != 0 {
			pc.Flush++
		} else {
			pc.FUA++
		}
		r.rep.Points++
		if e.Phase == "" || e.Phase == "setup" || r.rep.Points%max(1, *every) != 0 {
			pc.Skipped++
			return nil
		}
		pc.Checked++
		r.rep.Checked++
		began := time.Now()
		cerr := r.checkImage(ctx, work, e.Phase, &tr)
		status := "ok"
		if cerr != nil {
			status = "FAIL " + cerr.Error()
			r.rep.Failures = append(r.rep.Failures, failure{Point: r.rep.Points, Entry: e.Index, Phase: e.Phase, Error: cerr.Error()})
		}
		fmt.Fprintf(r.points, "point %d entry %d phase %s %v: %s\n", r.rep.Points, e.Index, e.Phase, time.Since(began).Round(time.Millisecond), status)
		if r.rep.Checked%25 == 0 || cerr != nil {
			fmt.Printf("point %d (%s): %d checked, %d failed\n", r.rep.Points, e.Phase, r.rep.Checked, len(r.rep.Failures))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	// Self-check: the whole log replayed must be the final device.
	if err := rp.Sync(); err != nil {
		t.Fatal(err)
	}
	got, err1 := fileSum(work)
	want, err2 := fileSum(data)
	switch {
	case err1 != nil || err2 != nil:
		r.rep.SelfCheck = fmt.Sprintf("%v %v", err1, err2)
	case got != want:
		r.rep.SelfCheck = fmt.Sprintf("the replayed image (%s) differs from the final device (%s): the replayer misread the log", got[:16], want[:16])
	default:
		r.rep.SelfCheck = "ok"
	}

	// The last point: the uninterrupted run's state.
	r.rep.FinalCheck = "ok"
	if err := r.checkImage(ctx, work, "end", &tr); err != nil {
		r.rep.FinalCheck = err.Error()
	} else if !slices.Equal(tr.Committed(), res.Committed) {
		r.rep.FinalCheck = fmt.Sprintf("the replay ends with %d batches committed, the run with %d", len(tr.Committed()), len(res.Committed))
	}
	r.rep.Pass = len(r.rep.Failures) == 0 && r.rep.SelfCheck == "ok" && r.rep.FinalCheck == "ok" && r.rep.Checked > 0
	fmt.Printf("%d crash points, %d checked, %d failed; self-check %s; final %s\n", r.rep.Points, r.rep.Checked, len(r.rep.Failures), r.rep.SelfCheck, r.rep.FinalCheck)
	if !r.rep.Pass {
		t.Fail()
	}
}
