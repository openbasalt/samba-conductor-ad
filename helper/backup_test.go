package helper

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBackupPolicyValidate(t *testing.T) {
	if err := DefaultBackupPolicy().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	bad := map[string]func(*BackupPolicy){
		"time":           func(p *BackupPolicy) { p.Schedule.Time = "24:00" },
		"time format":    func(p *BackupPolicy) { p.Schedule.Time = "2:30" },
		"every":          func(p *BackupPolicy) { p.Schedule.EveryHours = 5 },
		"daily zero":     func(p *BackupPolicy) { p.Retention.Daily = 0 },
		"weekly":         func(p *BackupPolicy) { p.Retention.Weekly = -1 },
		"monthly":        func(p *BackupPolicy) { p.Retention.Monthly = 121 },
		"max age":        func(p *BackupPolicy) { p.MaxAgeHours = 0 },
		"max age < slot": func(p *BackupPolicy) { p.Schedule.EveryHours = 24; p.MaxAgeHours = 12 },
		"drill":          func(p *BackupPolicy) { p.DrillIntervalDays = 91 },
	}
	for name, mutate := range bad {
		p := DefaultBackupPolicy()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBackupPolicyOverProtocol(t *testing.T) {
	p := DefaultBackupPolicy()
	p.Retention.Daily = 10
	req, err := NewRequest("req-00000002", OpBackupPolicySet, caller, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := req.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if gp := got.(*BackupPolicy); gp.Retention.Daily != 10 {
		t.Fatalf("decoded %+v", gp)
	}
	// Unknown fields (e.g. a destination or recipient) are refused.
	req.Params = json.RawMessage(`{"schedule":{"time":"02:30","every_hours":24},"retention":{"daily":7,"weekly":4,"monthly":12},"max_age_hours":26,"drill_interval_days":7,"recipients":["age1x"]}`)
	if _, err := req.Decode(); err == nil {
		t.Fatal("unknown policy field accepted")
	}
	if _, err := NewRequest("req-00000003", OpBackupTrigger, caller, BackupTriggerParams{Action: "restore"}); err == nil {
		t.Fatal("unknown trigger action accepted")
	}
	if _, err := NewRequest("req-00000003", OpBackupTrigger, caller, BackupTriggerParams{Action: TriggerDrill}); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleSlots(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	daily := BackupSchedule{Time: "02:30", EveryHours: 24}
	cases := []struct {
		s          BackupSchedule
		now, slot  string
		next       string
		descriptor string
	}{
		{daily, "2026-10-03T03:00:00Z", "2026-10-03T02:30:00Z", "2026-10-04T02:30:00Z", "after today's slot"},
		{daily, "2026-10-03T02:30:00Z", "2026-10-03T02:30:00Z", "2026-10-04T02:30:00Z", "exactly at the slot"},
		{daily, "2026-10-03T01:00:00Z", "2026-10-02T02:30:00Z", "2026-10-03T02:30:00Z", "before today's slot"},
		{BackupSchedule{Time: "02:30", EveryHours: 6}, "2026-10-03T01:00:00Z", "2026-10-02T20:30:00Z", "2026-10-03T02:30:00Z", "6h, early"},
		{BackupSchedule{Time: "02:30", EveryHours: 6}, "2026-10-03T15:00:00Z", "2026-10-03T14:30:00Z", "2026-10-03T20:30:00Z", "6h, afternoon"},
		{BackupSchedule{Time: "23:59", EveryHours: 1}, "2026-10-03T00:10:00Z", "2026-10-02T23:59:00Z", "2026-10-03T00:59:00Z", "hourly"},
	}
	for _, c := range cases {
		if got := c.s.Slot(at(c.now)); !got.Equal(at(c.slot)) {
			t.Errorf("%s: slot %s, want %s", c.descriptor, got, c.slot)
		}
		if got := c.s.Next(at(c.now)); !got.Equal(at(c.next)) {
			t.Errorf("%s: next %s, want %s", c.descriptor, got, c.next)
		}
	}
}

func TestStatusHelpers(t *testing.T) {
	s := BackupStatus{Backups: []BackupRecord{{ID: "c", Status: StatusFailed}, {ID: "b", Status: StatusPartial}, {ID: "a", Status: StatusOK}},
		Drills: []DrillRecord{{ID: "2", Passed: false}, {ID: "1", Passed: true}}}
	if b, ok := s.LastGood(); !ok || b.ID != "b" {
		t.Fatalf("last good %+v", b)
	}
	if d, ok := s.LastPassedDrill(); !ok || d.ID != "1" {
		t.Fatalf("last drill %+v", d)
	}
	// A full status must fit in one helper message.
	full := BackupStatus{Configured: true}
	for i := 0; i < 30; i++ {
		full.Backups = append(full.Backups, BackupRecord{ID: "20261003T011350Z-dc1", Status: StatusOK, SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Uploads: []UploadRecord{{Destination: "minio", Status: StatusOK}, {Destination: "local", Status: StatusOK}}, Error: strings.Repeat("e", 200)})
	}
	for i := 0; i < 10; i++ {
		d := DrillRecord{ID: "20261003T011350Z", BackupID: "20261003T011350Z-dc1", Host: "drill.example.com"}
		for j := 0; j < 12; j++ {
			d.Checks = append(d.Checks, DrillCheck{Name: "sid:user0001", OK: true, Detail: strings.Repeat("d", 120)})
		}
		full.Drills = append(full.Drills, d)
	}
	b, _ := json.Marshal(full)
	if len(b) > MaxMessageSize*3/4 {
		t.Fatalf("bounded status is %d bytes", len(b))
	}
}

func TestArchiveNamesAndIDs(t *testing.T) {
	for name, ok := range map[string]bool{
		"samba/samba-backup-lab.tar.bz2": true, "files/etc/samba/smb.conf": true, "conductor/conductor.db": true,
		"/etc/passwd": false, "../x": false, "samba/../../x": false, "a//b": false, "a/./b": false, "": false, "a\\b": false,
	} {
		if SafeMember(name) != ok {
			t.Errorf("SafeMember(%q) != %v", name, ok)
		}
	}
	at := time.Date(2026, 10, 3, 1, 13, 50, 0, time.UTC)
	id := NewBackupID(at, "DC1")
	if id != "20261003T011350Z-dc1" {
		t.Fatalf("id %q", id)
	}
	if got, err := BackupIDTime(id); err != nil || !got.Equal(at) {
		t.Fatalf("id time %v %v", got, err)
	}
	for _, bad := range []string{"20261003T011350Z", "20261003T011350Z-DC1", "2026-10-03-dc1", "20261003T011350Z-dc1/../x"} {
		if _, err := BackupIDTime(bad); err == nil {
			t.Errorf("id %q accepted", bad)
		}
	}
	m := ArchiveMeta{Format: ArchiveFormat, ID: id, Realm: "LAB.TEST", DC: "dc1", SambaFile: "samba/x.tar.bz2", Users: CountRange{Min: 5, Max: 6}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.SambaFile = "samba/../x"
	if err := m.Validate(); err == nil {
		t.Fatal("unsafe samba member accepted")
	}
	if !(CountRange{Min: 5, Max: 6}).Contains(6) || (CountRange{Min: 5, Max: 6}).Contains(7) {
		t.Fatal("range")
	}
}
