// Package ipset provides a basic wrapper to the ipset utility for IPTables.
// More information about ipset can be found at:
// http://ipset.netfilter.org/index.html
package ipset

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

type IPSet struct {
	Path    string
	Options []string
}

func New() (*IPSet, error) {
	binPath, err := exec.LookPath("ipset")
	if err != nil {
		return nil, err
	}

	return &IPSet{binPath, []string{}}, nil
}

// Create creates a new ipset with a given name and type.
// For more on set types, please see:
// http://ipset.netfilter.org/ipset.man.html#lbAT.
// Additional options can be passed to the Create() command. These options must
// be passed in a sequential key, value order.
// For example, ipset.Create("test", "hash:ip", "timeout", "300") will add a
// new set with the timeout option set to a value of 300.
func (set *IPSet) Create(name string, typ string, options ...string) error {
	_, err := set.run(append([]string{"create", name, typ}, options...)...)
	return err
}

// Add adds a new entry to the named set.
func (set *IPSet) Add(name string, entry string, options ...string) error {
	_, err := set.run(append([]string{"add", name, entry}, options...)...)
	return err
}

// AddUnique adds a new entry to the named set, if it does not already exist.
func (set *IPSet) AddUnique(name, entry string, options ...string) error {
	_, err := set.run(append([]string{"add", name, entry, "-exist"}, options...)...)
	return err
}

// Delete removes an entry from the named set.
func (set *IPSet) Delete(name string, entry string, options ...string) error {
	_, err := set.run(append([]string{"del", name, entry}, options...)...)
	return err
}

// Test tests if an entry exists in the named set.
// The exit status is zero if the tested entry is in the set, and nonzero if
// it is missing from the set.
func (set *IPSet) Test(name string, entry string, options ...string) error {
	_, err := set.run(append([]string{"test", name, entry}, options...)...)
	return err
}

// Destroy destroys a named set, or all sets.
func (set *IPSet) Destroy(name string) error {
	_, err := set.run("destroy", name)
	return err
}

// Save saves the named set or all sets to the given file.
func (set *IPSet) Save(name string, filename string) error {
	_, err := set.run("save", name, "-file", filename)
	return err
}

// Restore restores a saved set from the given file.
func (set *IPSet) Restore(filename string) error {
	_, err := set.run("restore", "-file", filename)
	return err
}

// Flush removes all entries from a named set.
func (set *IPSet) Flush(name string) error {
	_, err := set.run("flush", name)
	return err
}

// Rename changes a set name from one value to another.
func (set *IPSet) Rename(from string, to string) error {
	_, err := set.run("rename", from, to)
	return err
}

// Swap swaps the content of two existing sets.
func (set *IPSet) Swap(from string, to string) error {
	_, err := set.run("swap", from, to)
	return err
}

func (set *IPSet) List(name string) ([]string, error) {
	out, err := set.run("list", name)
	lines := strings.Split(out.String(), "\n")
	var start int
	for i, line := range lines {
		if strings.TrimSpace(line) == "Members:" {
			start = i
			break
		}
	}
	if len(lines) <= start+1 {
		return nil, err
	}

	var members []string
	for _, l := range lines[start+1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		members = append(members, l)
	}

	return members, err
}

func (set *IPSet) run(args ...string) (*bytes.Buffer, error) {
	var stderr, stdout bytes.Buffer
	cmd := exec.Cmd{
		Path:   set.Path,
		Args:   append([]string{set.Path}, args...),
		Stderr: &stderr,
		Stdout: &stdout,
	}

	if err := cmd.Run(); err != nil {
		return &stdout, errors.New(stderr.String())
	}

	return &stdout, nil
}
