package verify

import (
	"fmt"
	"io"
	"strings"
)

// Status is a check's outcome.
type Status string

// Check outcomes.
const (
	StatusOK      Status = "ok"
	StatusFail    Status = "FAIL"
	StatusSkipped Status = "skipped"
)

// maxProblems is how many findings a check keeps; it counts the rest.
const maxProblems = 100

// Check is one check's outcome.
type Check struct {
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Summary  string   `json:"summary"`            // what was checked, or why it was skipped
	Problems []string `json:"problems,omitempty"` // the first findings
	More     int      `json:"more_problems,omitempty"`
}

func (c *Check) fail(format string, args ...any) {
	c.Status = StatusFail
	if len(c.Problems) < maxProblems {
		c.Problems = append(c.Problems, fmt.Sprintf(format, args...))
	} else {
		c.More++
	}
}

// Report is what verify found (amendment A5 §1).
type Report struct {
	Mode     string   `json:"mode"` // quick or full
	AsOf     uint64   `json:"as_of_commit_seq"`
	Batches  int      `json:"batches"`
	Checks   []*Check `json:"checks"`
	Pending  []string `json:"recovery_pending,omitempty"` // a stopped writer's leftovers: not damage
	Writer   string   `json:"writer,omitempty"`           // a running writer, whose work in flight is not judged
	Warnings []string `json:"warnings,omitempty"`         // post-commit audit failures: not damage
}

// Damaged reports whether any check failed: exit 5.
func (r *Report) Damaged() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// Check returns the named check, nil if it did not run.
func (r *Report) Check(name string) *Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (r *Report) add(name string) *Check {
	c := &Check{Name: name, Status: StatusOK}
	r.Checks = append(r.Checks, c)
	return c
}

// shownProblems is how many findings a check shows in text.
const shownProblems = 10

// WriteText writes the report as `verify` prints it: one line per check,
// its first findings, what is pending, the warnings and the result.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "verify --%s: %s, as of commit_seq %d\n", r.Mode, count(r.Batches, "batch"), r.AsOf)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%-7s %s: %s\n", c.Status, c.Name, c.Summary)
		for i, p := range c.Problems {
			if i == shownProblems {
				break
			}
			fmt.Fprintf(w, "          %s\n", p)
		}
		if more := len(c.Problems) + c.More - min(len(c.Problems), shownProblems); more > 0 {
			fmt.Fprintf(w, "          … and %d more\n", more)
		}
	}
	if r.Writer != "" {
		fmt.Fprintf(w, "writer: %s\n", r.Writer)
	}
	for _, p := range r.Pending {
		fmt.Fprintf(w, "recovery pending: %s; the next update or rebuild finishes it\n", p)
	}
	for _, x := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
	var failed []string
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			failed = append(failed, c.Name)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(w, "result: damage found (%s)\n", strings.Join(failed, ", "))
		return
	}
	fmt.Fprintln(w, "result: no damage found")
}
