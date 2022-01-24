package auth

import (
	"errors"
	"fmt"
	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

type EtcShadowEntry struct {
	// User login name.
	Name string

	// Hashed user password.
	Pass string

	// Days since Jan 1, 1970 password was last changed.
	LastChange int

	// The number of days the user will have to wait before she will be allowed to
	// change her password again.
	//
	// -1 if password aging is disabled.
	MinPassAge int

	// The number of days after which the user will have to change her password.
	//
	// -1 is password aging is disabled.
	MaxPassAge int

	// The number of days before a password is going to expire (see the maximum
	// password age above) during which the user should be warned.
	//
	// -1 is password aging is disabled.
	WarnPeriod int

	// The number of days after a password has expired (see the maximum
	// password age above) during which the password should still be accepted.
	//
	// -1 is password aging is disabled.
	InactivityPeriod int

	// The date of expiration of the account, expressed as the number of days
	// since Jan 1, 1970.
	//
	// -1 is account never expires.
	AcctExpiry int

	// Unused now.
	Flags int
}

const secsInDay = 86400

func (e *EtcShadowEntry) IsAccountValid() bool {
	if e.AcctExpiry == -1 {
		return true
	}

	nowDays := int(time.Now().Unix() / secsInDay)
	return nowDays < e.AcctExpiry
}

func (e *EtcShadowEntry) IsPasswordValid() bool {
	if e.LastChange == -1 || e.MaxPassAge == -1 || e.InactivityPeriod == -1 {
		return true
	}

	nowDays := int(time.Now().Unix() / secsInDay)
	return nowDays < e.LastChange+e.MaxPassAge+e.InactivityPeriod
}

func (e *EtcShadowEntry) VerifyPassword(pass string) (err error) {
	// Do not permit null and locked passwords.
	if e.Pass == "" {
		return errors.New("verify: null password")
	}
	if e.Pass[0] == '!' {
		return errors.New("verify: locked password")
	}

	// crypt.NewFromHash may panic on unknown hash function.
	defer func() {
		if rcvr := recover(); rcvr != nil {
			err = fmt.Errorf("%v", rcvr)
		}
	}()

	if err := crypt.NewFromHash(e.Pass).Verify(e.Pass, []byte(pass)); err != nil {
		if errors.Is(err, crypt.ErrKeyMismatch) {
			return ErrWrongPassword
		}
		return err
	}
	return nil
}

type EtcShadow struct {
	entries        []*EtcShadowEntry
	nameMap        map[string]*EtcShadowEntry
	ignoreBadLines bool
}

// NewEmptyEtcShadow returns an empty passwd cache.
func NewEmptyEtcShadow(ignoreBadLines bool) *EtcShadow {
	return &EtcShadow{
		ignoreBadLines: ignoreBadLines,
	}
}

// NewEtcShadow returns a loaded passwd cache in a single call.
func NewEtcShadow() (*EtcShadow, error) {
	result := NewEmptyEtcShadow(true)
	if err := result.LoadDefault(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadDefault loads the struct from the /etc/passwd file
func (e *EtcShadow) LoadDefault() error {
	return e.LoadFromPath("/etc/shadow")
}

// ParseShadowLine is a function used to parse a 7 entry /etc/passwd line formatted line
// into a EtcShadowEntry object.
func ParseShadowLine(line string) (*EtcShadowEntry, error) {
	parts := strings.Split(line, ":")
	if len(parts) != 9 {
		return nil, errors.New("read: malformed entry")
	}

	res := &EtcShadowEntry{
		Name: parts[0],
		Pass: parts[1],
	}

	for i, value := range [...]*int{
		&res.LastChange, &res.MinPassAge, &res.MaxPassAge,
		&res.WarnPeriod, &res.InactivityPeriod, &res.AcctExpiry, &res.Flags,
	} {
		if parts[2+i] == "" {
			*value = -1
		} else {
			var err error
			*value, err = strconv.Atoi(parts[2+i])
			if err != nil {
				return nil, fmt.Errorf("read: invalid value for field %d", 2+i)
			}
		}
	}

	return res, nil
}

// AddEntry adds an entry object to the cache object and links it into the lookup maps.
// Overrides any existing item in the lookup maps.
func (e *EtcShadow) AddEntry(entry *EtcShadowEntry) {
	e.entries = append(e.entries, entry)
	e.nameMap[entry.Name] = entry
}

// LoadFromPath loads the struct from a file on disk and replaces the cached content.
func (e *EtcShadow) LoadFromPath(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	e.entries = make([]*EtcShadowEntry, 0)
	e.nameMap = make(map[string]*EtcShadowEntry)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// skip commented or empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		// parse the current line
		entry, err := ParseShadowLine(line)
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

// LookupUserByName returns the entry for the given username
func (e *EtcShadow) LookupUserByName(name string) (*EtcShadowEntry, error) {
	entry, ok := e.nameMap[name]
	if !ok {
		return nil, fmt.Errorf(ErrNoSuchUserName, name)
	}
	return entry, nil
}
