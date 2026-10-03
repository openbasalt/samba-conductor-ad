package helper

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Domain backups (P3). conductor-helper serves two peers with different
// operation sets (checked with SO_PEERCRED):
//
//   - conductor-backup (the backup service user) may only ask for
//     OpDomainBackupOnline: the helper runs samba-tool with the backup
//     account, builds the archive, encrypts it to the recipients in a
//     root-owned file and leaves only ciphertext in conductor-backup's spool
//     directory. Nothing in the request chooses where data goes or who can
//     decrypt it.
//   - conductor (the web user) may read the backup status, ask for a backup
//     or a restore drill (a request file that conductor-backup.path turns
//     into a run) and change the backup policy (schedule,
//     retention, alert threshold, drill interval). Destinations,
//     credentials and recipients are host configuration, never changed
//     through the web.

// Backup operations.
const (
	OpBackupStatus    OpName = "backup.status"
	OpBackupTrigger   OpName = "backup.trigger"
	OpBackupPolicySet OpName = "backup.policy.set"
)

// Trigger actions.
const (
	TriggerBackup = "backup"
	TriggerDrill  = "drill"
)

// BackupTriggerParams asks for a backup or a restore drill now.
type BackupTriggerParams struct {
	Action string `json:"action"`
}

// Validate implements Params.
func (p BackupTriggerParams) Validate() error {
	if p.Action != TriggerBackup && p.Action != TriggerDrill {
		return fmt.Errorf("action %q is not %q or %q", p.Action, TriggerBackup, TriggerDrill)
	}
	return nil
}

// BackupTriggerResult answers OpBackupTrigger. The helper only writes the
// request file; conductor-backup.path (a systemd path unit watching the
// requests directory) starts conductor-backup, which processes it.
type BackupTriggerResult struct {
	RequestID string `json:"request_id"`
}

// BackupPolicy is the part of the backup configuration administrators may
// change from the web interface. Times are UTC.
type BackupPolicy struct {
	Schedule  BackupSchedule  `json:"schedule"`
	Retention BackupRetention `json:"retention"`
	// MaxAgeHours: older than this, the last good backup is "stale"
	// (dashboard banner, alert e-mail).
	MaxAgeHours int `json:"max_age_hours"`
	// DrillIntervalDays: a restore drill is requested when the last one is
	// older than this; 0 = drills only on demand.
	DrillIntervalDays int `json:"drill_interval_days"`
}

// BackupSchedule: a backup at Time (HH:MM UTC) and then every EveryHours.
type BackupSchedule struct {
	Time       string `json:"time"`
	EveryHours int    `json:"every_hours"`
}

// BackupRetention keeps the newest successful backup of each of the last
// Daily days, Weekly ISO weeks and Monthly months (grandfather-father-son).
// The last successful backup is always kept.
type BackupRetention struct {
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// DefaultBackupPolicy is used until an administrator saves another one.
func DefaultBackupPolicy() BackupPolicy {
	return BackupPolicy{
		Schedule:          BackupSchedule{Time: "02:30", EveryHours: 24},
		Retention:         BackupRetention{Daily: 7, Weekly: 4, Monthly: 12},
		MaxAgeHours:       26,
		DrillIntervalDays: 7,
	}
}

var hhmmRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ValidEveryHours are the schedule intervals (divisors of 24, so a slot
// falls at the same times every day).
var ValidEveryHours = []int{1, 2, 3, 4, 6, 8, 12, 24}

// Validate implements Params.
func (p BackupPolicy) Validate() error {
	var errs []error
	if !hhmmRE.MatchString(p.Schedule.Time) {
		errs = append(errs, errors.New("schedule time must be HH:MM (UTC)"))
	}
	if !slices.Contains(ValidEveryHours, p.Schedule.EveryHours) {
		errs = append(errs, fmt.Errorf("schedule interval must be one of %v hours", ValidEveryHours))
	}
	r := p.Retention
	if r.Daily < 1 || r.Daily > 366 || r.Weekly < 0 || r.Weekly > 260 || r.Monthly < 0 || r.Monthly > 120 {
		errs = append(errs, errors.New("retention: daily 1-366, weekly 0-260, monthly 0-120"))
	}
	if p.MaxAgeHours < 1 || p.MaxAgeHours > 720 {
		errs = append(errs, errors.New("maximum age must be 1-720 hours"))
	} else if p.MaxAgeHours < p.Schedule.EveryHours {
		errs = append(errs, errors.New("maximum age must be at least the schedule interval"))
	}
	if p.DrillIntervalDays < 0 || p.DrillIntervalDays > 90 {
		errs = append(errs, errors.New("drill interval must be 0-90 days"))
	}
	return errors.Join(errs...)
}

// Slot returns the most recent scheduled slot at or before t (UTC).
func (s BackupSchedule) Slot(t time.Time) time.Time {
	t = t.UTC()
	var h, m int
	_, _ = fmt.Sscanf(s.Time, "%d:%d", &h, &m)
	every := s.EveryHours
	if every <= 0 {
		every = 24
	}
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	// The slots of a day: Time, Time+every, … wrapped to the day.
	first := time.Duration(h)*time.Hour + time.Duration(m)*time.Minute
	first %= time.Duration(every) * time.Hour
	slot := day.Add(first)
	for slot.Add(time.Duration(every)*time.Hour).Compare(t) <= 0 {
		slot = slot.Add(time.Duration(every) * time.Hour)
	}
	if slot.After(t) {
		slot = slot.Add(-time.Duration(every) * time.Hour)
	}
	return slot
}

// Next returns the first scheduled slot after t.
func (s BackupSchedule) Next(t time.Time) time.Time {
	every := s.EveryHours
	if every <= 0 {
		every = 24
	}
	return s.Slot(t).Add(time.Duration(every) * time.Hour)
}

// BackupOnlineParams asks for an online domain backup. The helper chooses
// the work and output directories, the account and the recipients from its
// own configuration; the caller only labels the run.
// (Defined in protocol.go; Label is "scheduled" or "manual".)

// BackupOnlineResult answers OpDomainBackupOnline: an encrypted archive is
// in the spool directory.
type BackupOnlineResult struct {
	// ID is "<UTC timestamp>-<dc>", e.g. "20261003T011350Z-dc1".
	ID string `json:"id"`
	// File is the archive's base name in the spool directory.
	File      string    `json:"file"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	MD5       string    `json:"md5"`
	CreatedAt time.Time `json:"created_at"`
	Realm     string    `json:"realm"`
	DC        string    `json:"dc"`
	// Recipients are the fingerprints of the age recipients it was
	// encrypted to.
	Recipients []string          `json:"recipients"`
	Versions   map[string]string `json:"versions"`
	// Contents lists the archive members.
	Contents []string `json:"contents"`
	// Users and Groups counted in the directory when the backup was taken.
	Users      int   `json:"users"`
	Groups     int   `json:"groups"`
	DurationMS int64 `json:"duration_ms"`
}

// BackupStatus is conductor-backup's state as conductor shows it
// (OpBackupStatus). conductor-backup writes it (state.json); the helper
// reads it for conductor. Lists are bounded so it stays far below
// MaxMessageSize.
type BackupStatus struct {
	// Configured is false when conductor-backup is not installed or has
	// never run on this host.
	Configured bool      `json:"configured"`
	Realm      string    `json:"realm,omitempty"`
	DC         string    `json:"dc,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	// LastRunAt is the last time conductor-backup ran (scheduler liveness).
	LastRunAt time.Time    `json:"last_run_at"`
	NextDueAt time.Time    `json:"next_due_at"`
	Policy    BackupPolicy `json:"policy"`
	// PolicyCustom is true when an administrator saved the policy.
	PolicyCustom bool                `json:"policy_custom"`
	Destinations []BackupDestination `json:"destinations"`
	// Recipients are fingerprints of the age recipients (public keys).
	Recipients   []string        `json:"recipients"`
	SigningKeyID string          `json:"signing_key_id,omitempty"`
	Backups      []BackupRecord  `json:"backups"`
	Drills       []DrillRecord   `json:"drills"`
	Pending      []BackupRequest `json:"pending"`
	Alerts       []BackupAlert   `json:"alerts"`
	Version      string          `json:"version,omitempty"`
}

// BackupDestination describes where backups go, without credentials.
type BackupDestination struct {
	Name string `json:"name"`
	Type string `json:"type"` // "local" or "s3"
	// Location: a directory, or endpoint host + bucket + prefix.
	Location       string `json:"location"`
	ObjectLockDays int    `json:"object_lock_days,omitempty"`
}

// Backup record statuses.
const (
	StatusOK      = "ok"      // archived, uploaded and verified everywhere
	StatusPartial = "partial" // at least one destination failed
	StatusFailed  = "failed"  // nothing usable
	StatusPruned  = "pruned"  // removed by the retention policy
)

// BackupRecord is one backup run.
type BackupRecord struct {
	ID          string         `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	Trigger     string         `json:"trigger"` // "scheduled" or "manual"
	RequestedBy string         `json:"requested_by,omitempty"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Size        int64          `json:"size"`
	SHA256      string         `json:"sha256,omitempty"`
	Users       int            `json:"users"`
	DurationMS  int64          `json:"duration_ms"`
	Uploads     []UploadRecord `json:"uploads"`
}

// UploadRecord is one destination of a backup.
type UploadRecord struct {
	Destination string    `json:"destination"`
	Status      string    `json:"status"` // ok, failed, pruned
	Error       string    `json:"error,omitempty"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// DrillRecord is one restore drill, as reported (signed) by the drill host.
type DrillRecord struct {
	ID         string       `json:"id"`
	BackupID   string       `json:"backup_id"`
	RequestID  string       `json:"request_id,omitempty"`
	Host       string       `json:"host"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Passed     bool         `json:"passed"`
	Error      string       `json:"error,omitempty"`
	RTOMS      int64        `json:"rto_ms"`
	Checks     []DrillCheck `json:"checks"`
}

// DrillCheck is one verification of a drill.
type DrillCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// BackupRequest is a "back up now" or "run drill now" waiting to be
// processed.
type BackupRequest struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // TriggerBackup or TriggerDrill
	RequestedBy string    `json:"requested_by"`
	SID         string    `json:"sid"`
	At          time.Time `json:"at"`
}

// Alert kinds.
const (
	AlertStale        = "stale"         // last good backup older than the policy
	AlertFailed       = "failed"        // the last run failed
	AlertDrillFailed  = "drill_failed"  // the last drill failed
	AlertDrillOverdue = "drill_overdue" // no drill result within the interval
	AlertScheduler    = "scheduler"     // conductor-backup has not run lately
)

// BackupAlert is an active alert condition.
type BackupAlert struct {
	Kind   string    `json:"kind"`
	Since  time.Time `json:"since"`
	Detail string    `json:"detail,omitempty"`
}

// LastGood returns the newest backup with status ok (or partial: usable at
// one destination at least), if any.
func (s BackupStatus) LastGood() (BackupRecord, bool) {
	for _, b := range s.Backups {
		if b.Status == StatusOK || b.Status == StatusPartial {
			return b, true
		}
	}
	return BackupRecord{}, false
}

// LastPassedDrill returns the newest passing drill, if any.
func (s BackupStatus) LastPassedDrill() (DrillRecord, bool) {
	for _, d := range s.Drills {
		if d.Passed {
			return d, true
		}
	}
	return DrillRecord{}, false
}
