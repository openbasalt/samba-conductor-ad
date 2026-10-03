package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// The backup archive is an uncompressed tar stream, encrypted with age
// (filippo.io/age) by conductor-helper before it is written anywhere. Its
// members:
//
//	conductor-backup.json          ArchiveMeta (always first)
//	samba/<samba-backup-….tar.bz2> the `samba-tool domain backup online` file
//	conductor/conductor.db         conductor's SQLite state, sessions removed
//	                               (TOTP secrets stay sealed with the key
//	                               that never leaves /etc/conductor/credentials)
//	files/<absolute path>          host files a full recovery needs
//	                               (smb.conf, krb5.conf, the conductor and
//	                               backup configs, the DC's TLS files)
const (
	ArchiveFormat      = "conductor-backup-archive/1"
	ArchiveMetaName    = "conductor-backup.json"
	ArchiveSambaDir    = "samba/"
	ArchiveConductorDB = "conductor/conductor.db"
	ArchiveFilesDir    = "files/"
)

// ArchiveMeta describes an archive and the directory it was taken from.
// The counts and samples let a restore drill compare the restored domain
// with the source.
type ArchiveMeta struct {
	Format    string            `json:"format"`
	ID        string            `json:"id"`
	Realm     string            `json:"realm"`
	DC        string            `json:"dc"`
	CreatedAt time.Time         `json:"created_at"`
	Versions  map[string]string `json:"versions"`
	DomainSID string            `json:"domain_sid"`
	// Users and Groups are counted before and after samba-tool ran; a
	// restored copy must fall within [Min, Max].
	Users  CountRange `json:"users"`
	Groups CountRange `json:"groups"`
	// Samples are objects whose SIDs must survive a restore unchanged.
	Samples []ArchiveSample `json:"samples"`
	// SambaFile is the archive member holding the samba-tool backup.
	SambaFile   string   `json:"samba_file"`
	ConductorDB bool     `json:"conductor_db"`
	Files       []string `json:"files"`
	// TLS lists the DC's TLS files named in smb.conf, so a restore can put
	// them where the restored smb.conf expects them.
	TLS []ArchiveTLSFile `json:"tls,omitempty"`
}

// ArchiveTLSFile is one "tls certfile|keyfile|cafile" of smb.conf.
type ArchiveTLSFile struct {
	// Param is "certfile", "keyfile" or "cafile".
	Param string `json:"param"`
	// Value as written in smb.conf (relative values are relative to the
	// private directory).
	Value string `json:"value"`
	// Member is the archive member (files/<absolute path>).
	Member string `json:"member"`
}

// CountRange is a count taken twice around the backup.
type CountRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Contains reports whether n is within the range.
func (r CountRange) Contains(n int) bool { return n >= r.Min && n <= r.Max }

// ArchiveSample is one object whose SID a drill checks.
type ArchiveSample struct {
	Kind string `json:"kind"` // "user" or "group"
	Name string `json:"name"` // sAMAccountName
	SID  string `json:"sid"`
}

// BackupIDRE matches backup IDs: "<UTC timestamp>-<dc>".
var BackupIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-z0-9][a-z0-9-]{0,62}$`)

// BackupIDTime returns the creation time encoded in a backup ID.
func BackupIDTime(id string) (time.Time, error) {
	if !BackupIDRE.MatchString(id) {
		return time.Time{}, fmt.Errorf("invalid backup id %q", id)
	}
	return time.Parse("20060102T150405Z", id[:16])
}

// NewBackupID builds the ID of a backup taken at t on dc.
func NewBackupID(t time.Time, dc string) string {
	return t.UTC().Format("20060102T150405Z") + "-" + strings.ToLower(dc)
}

// Validate checks what a reader relies on.
func (m ArchiveMeta) Validate() error {
	if m.Format != ArchiveFormat {
		return fmt.Errorf("archive format %q, want %q", m.Format, ArchiveFormat)
	}
	if !BackupIDRE.MatchString(m.ID) {
		return fmt.Errorf("invalid backup id %q", m.ID)
	}
	if m.Realm == "" || m.DC == "" {
		return errors.New("archive without realm or DC")
	}
	if !strings.HasPrefix(m.SambaFile, ArchiveSambaDir) || !SafeMember(m.SambaFile) {
		return fmt.Errorf("invalid samba member %q", m.SambaFile)
	}
	if m.Users.Min < 0 || m.Users.Max < m.Users.Min {
		return errors.New("invalid user count range")
	}
	return nil
}

// SafeMember reports whether a tar member name is a clean relative path
// (no absolute paths, no "..", no empty or dot segments), so extracting it
// cannot leave the target directory.
func SafeMember(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") || len(name) > 1024 {
		return false
	}
	if path.Clean(name) != name {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// RecipientFingerprint identifies an age recipient (public key) in
// manifests and the UI: "SHA256:" and the first 16 hex digits of the
// SHA-256 of its text form, e.g. "SHA256:3f9a0c1d2b4e5f60".
func RecipientFingerprint(recipient string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(recipient)))
	return "SHA256:" + hex.EncodeToString(sum[:8])
}
