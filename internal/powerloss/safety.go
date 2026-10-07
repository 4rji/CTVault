package powerloss

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// dmPrefix names this gate's device-mapper targets.
const dmPrefix = "ctvault-powerloss-"

// dmName is the run's one target (amendment A5 §13).
func dmName(pid int) string { return fmt.Sprintf("%s%d", dmPrefix, pid) }

// loopDevice is a loop device and the file behind it, as losetup lists it.
type loopDevice struct {
	Name     string `json:"name"`
	BackFile string `json:"back-file"`
}

// parseLosetup reads `losetup --json --list`.
func parseLosetup(b []byte) ([]loopDevice, error) {
	var out struct {
		Devices []loopDevice `json:"loopdevices"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("losetup --json --list: %w", err)
	}
	return out.Devices, nil
}

var loopName = regexp.MustCompile(`^/dev/loop[0-9]+$`)

// checkLoop refuses a device that is not a /dev/loopN attached to file, the
// run's own: nothing else is ever formatted or mounted (amendment A5 §13).
func checkLoop(devs []loopDevice, dev, file string) error {
	if !loopName.MatchString(dev) {
		return fmt.Errorf("refusing %q: not a /dev/loopN device", dev)
	}
	for _, d := range devs {
		if d.Name == dev {
			if d.BackFile != file {
				return fmt.Errorf("refusing %s: it is attached to %q, not %q", dev, d.BackFile, file)
			}
			return nil
		}
	}
	return fmt.Errorf("refusing %s: losetup does not list it", dev)
}

// leftovers lists what an earlier run left: this gate's device-mapper
// targets (from `dmsetup ls`) and loop devices backed by files under base.
// They are reported, never removed.
func leftovers(dmls string, devs []loopDevice, base string) []string {
	var out []string
	for _, line := range strings.Split(dmls, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], dmPrefix) {
			out = append(out, "device-mapper target "+f[0])
		}
	}
	for _, d := range devs {
		if strings.HasPrefix(d.BackFile, strings.TrimSuffix(base, "/")+"/") {
			out = append(out, fmt.Sprintf("loop device %s (%s)", d.Name, d.BackFile))
		}
	}
	return out
}
