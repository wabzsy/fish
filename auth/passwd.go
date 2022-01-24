// Package auth provides straightforward functionality for loading an /etc/passwd file
// and doing lookups on its content.
//
// Remember this only looks at an /etc/passwd type file, so will work best on Linux operating systems
// and wont pick up users from LDAP and other sources.
package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

// EtcPasswdEntry is a parsed line from the etc passwd file. It contains all 7 parts of the structure.
// Remember that the password field is encrypted or refers to an item in an alternative authentication scheme.
type EtcPasswdEntry struct {
	username string
	password string
	uid      uint32
	gid      uint32
	info     string
	homedir  string
	shell    string
}

// Username function returns the username string for the entry
func (e *EtcPasswdEntry) Username() string {
	return e.username
}

// Password function returns the encrypted password string for the entry
func (e *EtcPasswdEntry) Password() string {
	return e.password
}

func (e *EtcPasswdEntry) Verify(password string) error {
	shadow, err := NewEtcShadow()
	if err != nil {
		return err
	}

	shadowEntry, err := shadow.LookupUserByName(e.username)
	if err != nil {
		return err
	}

	if !(shadowEntry.IsAccountValid() && shadowEntry.IsPasswordValid()) {
		return errors.New("account or password is invalid")
	}
	return shadowEntry.VerifyPassword(password)
}

// Uid function returns the user id for the entry
func (e *EtcPasswdEntry) Uid() uint32 {
	return e.uid
}

// Gid function returns the group id for the entry
func (e *EtcPasswdEntry) Gid() uint32 {
	return e.gid
}

// Info function returns the info string for the entry
func (e *EtcPasswdEntry) Info() string {
	return e.info
}

// Homedir function returns the home directory for the entry
func (e *EtcPasswdEntry) Homedir() string {
	return e.homedir
}

// Shell function returns the users shell
func (e *EtcPasswdEntry) Shell() string {
	return e.shell
}

// EtcPasswd is an object that stores a set of entries from the passwd file and
// has quick lookup functions.
type EtcPasswd struct {
	entries        []*EtcPasswdEntry
	nameMap        map[string]*EtcPasswdEntry
	idMap          map[uint32]*EtcPasswdEntry
	ignoreBadLines bool
}

// ParsePasswdLine is a function used to parse a 7 entry /etc/passwd line formatted line
// into a EtcPasswdEntry object.
func ParsePasswdLine(line string) (*EtcPasswdEntry, error) {
	result := &EtcPasswdEntry{}
	parts := strings.Split(strings.TrimSpace(line), ":")
	if len(parts) != 7 {
		return result, fmt.Errorf("passwd line had wrong number of parts %d != 7", len(parts))
	}
	result.username = strings.TrimSpace(parts[0])
	result.password = strings.TrimSpace(parts[1])

	uid, err := strconv.Atoi(parts[2])
	if err != nil {
		return result, fmt.Errorf("passwd line had badly formatted uid %s", parts[2])
	}
	result.uid = uint32(uid)

	gid, err := strconv.Atoi(parts[3])
	if err != nil {
		return result, fmt.Errorf("passwd line had badly formatted gid %s", parts[2])
	}
	result.gid = uint32(gid)

	result.info = strings.TrimSpace(parts[4])
	result.homedir = strings.TrimSpace(parts[5])
	result.shell = strings.TrimSpace(parts[6])
	return result, nil
}

// AddEntry adds an entry object to the cache object and links it into the lookup maps.
// Overrides any existing item in the lookup maps.
func (e *EtcPasswd) AddEntry(entry *EtcPasswdEntry) {
	e.entries = append(e.entries, entry)
	e.nameMap[entry.username] = entry
	e.idMap[entry.uid] = entry
}

// LoadFromPath loads the struct from a file on disk and replaces the cached content.
func (e *EtcPasswd) LoadFromPath(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	e.entries = make([]*EtcPasswdEntry, 0)
	e.nameMap = make(map[string]*EtcPasswdEntry)
	e.idMap = make(map[uint32]*EtcPasswdEntry)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// skip commented or empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		// parse the current line
		entry, err := ParsePasswdLine(line)
		if err != nil {
			if e.ignoreBadLines {
				continue
			}
			return err
		}
		e.AddEntry(entry)
	}
	return nil
}

// NewEmptyEtcPasswd returns an empty passwd cache.
func NewEmptyEtcPasswd(ignoreBadLines bool) *EtcPasswd {
	return &EtcPasswd{
		ignoreBadLines: ignoreBadLines,
	}
}

// NewEtcPasswd returns a loaded passwd cache in a single call.
func NewEtcPasswd() (*EtcPasswd, error) {
	result := NewEmptyEtcPasswd(true)
	if err := result.LoadDefault(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadDefault loads the struct from the /etc/passwd file
func (e *EtcPasswd) LoadDefault() error {
	return e.LoadFromPath("/etc/passwd")
}

// LookupUserByName returns the entry for the given username
func (e *EtcPasswd) LookupUserByName(name string) (*EtcPasswdEntry, error) {
	entry, ok := e.nameMap[name]
	if !ok {
		return nil, fmt.Errorf(ErrNoSuchUserName, name)
	}
	return entry, nil
}

// LookupUserByUid returns the entry for the given userid
func (e *EtcPasswd) LookupUserByUid(id uint32) (*EtcPasswdEntry, error) {
	entry, ok := e.idMap[id]
	if !ok {
		return nil, fmt.Errorf(ErrNoSuchUserId, id)
	}
	return entry, nil
}

// UidForUsername is a shortcut function to get the user id for the given username.
// Useful when needing to chown a file.
func (e *EtcPasswd) UidForUsername(name string) (uint32, error) {
	entry, err := e.LookupUserByName(name)
	if err != nil {
		return 0, err
	}
	return entry.Uid(), nil
}

// HomeDirForUsername is a shortcut function to get the home directory for the given username.
// Useful when needing to store things in the home directory.
func (e *EtcPasswd) HomeDirForUsername(name string) (string, error) {
	entry, err := e.LookupUserByName(name)
	if err != nil {
		return "", err
	}
	return entry.Homedir(), nil
}

// ListEntries returns a slice containing references to all the entry objects
func (e *EtcPasswd) ListEntries() []*EtcPasswdEntry {
	results := make([]*EtcPasswdEntry, len(e.entries))
	for i, entry := range e.entries {
		results[i] = entry
	}
	return results
}
