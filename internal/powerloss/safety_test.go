package powerloss

import (
	"strings"
	"testing"
)

const losetupJSON = `{
   "loopdevices": [
      {"name": "/dev/loop0", "sizelimit": 0, "offset": 0, "autoclear": false, "ro": false, "back-file": "/var/lib/snapd/snaps/core.snap", "dio": false, "log-sec": 512},
      {"name": "/dev/loop7", "sizelimit": 0, "offset": 0, "autoclear": false, "ro": false, "back-file": "/mnt/disk/ctvault/powerloss/run-1/data.img", "dio": false, "log-sec": 512},
      {"name": "/dev/loop8", "sizelimit": 0, "offset": 0, "autoclear": false, "ro": false, "back-file": "/mnt/disk/ctvault/powerloss/run-0/log.img (deleted)", "dio": false, "log-sec": 512}
   ]
}`

// TestCheckLoop: a device is used only if it is a /dev/loopN attached to
// the run's own file (amendment A5 §13).
func TestCheckLoop(t *testing.T) {
	devs, err := parseLosetup([]byte(losetupJSON))
	if err != nil || len(devs) != 3 {
		t.Fatalf("%v %v", devs, err)
	}
	data := "/mnt/disk/ctvault/powerloss/run-1/data.img"
	if err := checkLoop(devs, "/dev/loop7", data); err != nil {
		t.Fatal(err)
	}
	for dev, file := range map[string]string{
		"/dev/sda":     data,
		"/dev/loop7p1": data,
		"/dev/loop0":   data,
		"/dev/loop9":   data,
		"/dev/loop7 ":  data,
	} {
		if err := checkLoop(devs, dev, file); err == nil {
			t.Errorf("%q accepted for %s", dev, file)
		}
	}
	if err := checkLoop(devs, "/dev/loop7", "/mnt/disk/ctvault/powerloss/run-1/log.img"); err == nil {
		t.Error("a loop device attached to another file accepted")
	}
	if _, err := parseLosetup([]byte("not json")); err == nil {
		t.Error("unparsable losetup output accepted")
	}
}

// TestLeftovers: a target or a loop device an earlier run left is found, to
// be reported, never removed.
func TestLeftovers(t *testing.T) {
	devs, _ := parseLosetup([]byte(losetupJSON))
	got := leftovers("ctvault-powerloss-41\t(253:3)\nother-target\t(253:0)\n", devs, "/mnt/disk/ctvault/powerloss")
	want := []string{"device-mapper target ctvault-powerloss-41", "loop device /dev/loop7 (/mnt/disk/ctvault/powerloss/run-1/data.img)", "loop device /dev/loop8 (/mnt/disk/ctvault/powerloss/run-0/log.img (deleted))"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("leftovers %q", got)
	}
	if got := leftovers("No devices found\n", nil, "/x"); len(got) != 0 {
		t.Fatalf("no leftovers: %q", got)
	}
	if n := dmName(1234); n != "ctvault-powerloss-1234" {
		t.Fatal(n)
	}
}
