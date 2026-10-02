package ad

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad/sid"
)

// UAC is userAccountControl (MS-ADTS 2.2.16).
type UAC uint32

// userAccountControl flags.
const (
	UACScript                     UAC = 0x0001
	UACAccountDisable             UAC = 0x0002
	UACHomedirRequired            UAC = 0x0008
	UACLockout                    UAC = 0x0010
	UACPasswdNotRequired          UAC = 0x0020
	UACPasswdCantChange           UAC = 0x0040
	UACEncryptedTextPwdAllowed    UAC = 0x0080
	UACNormalAccount              UAC = 0x0200
	UACInterdomainTrustAccount    UAC = 0x0800
	UACWorkstationTrustAccount    UAC = 0x1000
	UACServerTrustAccount         UAC = 0x2000
	UACDontExpirePassword         UAC = 0x10000
	UACSmartcardRequired          UAC = 0x40000
	UACTrustedForDelegation       UAC = 0x80000
	UACNotDelegated               UAC = 0x100000
	UACUseDESKeyOnly              UAC = 0x200000
	UACDontRequirePreauth         UAC = 0x400000
	UACPasswordExpired            UAC = 0x800000
	UACTrustedToAuthForDelegation UAC = 0x1000000
)

var uacNames = []struct {
	f    UAC
	name string
}{
	{UACScript, "SCRIPT"}, {UACAccountDisable, "ACCOUNTDISABLE"}, {UACHomedirRequired, "HOMEDIR_REQUIRED"},
	{UACLockout, "LOCKOUT"}, {UACPasswdNotRequired, "PASSWD_NOTREQD"}, {UACPasswdCantChange, "PASSWD_CANT_CHANGE"},
	{UACEncryptedTextPwdAllowed, "ENCRYPTED_TEXT_PWD_ALLOWED"}, {UACNormalAccount, "NORMAL_ACCOUNT"},
	{UACInterdomainTrustAccount, "INTERDOMAIN_TRUST_ACCOUNT"}, {UACWorkstationTrustAccount, "WORKSTATION_TRUST_ACCOUNT"},
	{UACServerTrustAccount, "SERVER_TRUST_ACCOUNT"}, {UACDontExpirePassword, "DONT_EXPIRE_PASSWORD"},
	{UACSmartcardRequired, "SMARTCARD_REQUIRED"}, {UACTrustedForDelegation, "TRUSTED_FOR_DELEGATION"},
	{UACNotDelegated, "NOT_DELEGATED"}, {UACUseDESKeyOnly, "USE_DES_KEY_ONLY"},
	{UACDontRequirePreauth, "DONT_REQ_PREAUTH"}, {UACPasswordExpired, "PASSWORD_EXPIRED"},
	{UACTrustedToAuthForDelegation, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
}

// Has reports whether every bit of f is set.
func (u UAC) Has(f UAC) bool { return u&f == f }

// String lists the set flags, e.g. "NORMAL_ACCOUNT|ACCOUNTDISABLE".
func (u UAC) String() string {
	var parts []string
	rest := u
	for _, n := range uacNames {
		if u&n.f != 0 {
			parts = append(parts, n.name)
			rest &^= n.f
		}
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", uint32(rest)))
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, "|")
}

// FileTime is an AD 64-bit timestamp: 100 ns intervals since 1601-01-01 UTC.
type FileTime int64

const filetimeEpochDelta = 116444736000000000 // 1601 -> 1970 in 100 ns

// Never is the "no expiry" value of accountExpires.
const Never FileTime = math.MaxInt64

// Time converts to time.Time; zero (and Never) give the zero time.
func (f FileTime) Time() time.Time {
	if f <= 0 || f == Never {
		return time.Time{}
	}
	return time.Unix(0, (int64(f)-filetimeEpochDelta)*100).UTC()
}

// FileTimeFrom converts a time to FileTime.
func FileTimeFrom(t time.Time) FileTime {
	return FileTime(t.UnixNano()/100 + filetimeEpochDelta)
}

// String renders the integer form used on the wire.
func (f FileTime) String() string { return strconv.FormatInt(int64(f), 10) }

// Entry attribute lists for the typed models.
var (
	UserAttributes = []string{"distinguishedName", "objectGUID", "objectSid", "sAMAccountName", "userPrincipalName",
		"displayName", "givenName", "sn", "mail", "description", "department", "title", "userAccountControl",
		"msDS-User-Account-Control-Computed", "pwdLastSet", "lockoutTime", "accountExpires", "lastLogonTimestamp",
		"memberOf", "primaryGroupID", "whenCreated", "whenChanged", "telephoneNumber", "mobile", "homePhone",
		"physicalDeliveryOfficeName", "company", "streetAddress", "l", "st", "postalCode", "wWWHomePage",
		"badPwdCount", "badPasswordTime", "whenCreated"}
	// UserExpiryAttributes adds the constructed password expiry time. The
	// DC computes it per entry (it about doubles the cost of a large
	// search), so it is only read where needed.
	UserExpiryAttributes = append(append([]string(nil), UserAttributes...), "msDS-UserPasswordExpiryTimeComputed")
	GroupAttributes      = []string{"distinguishedName", "objectGUID", "objectSid", "sAMAccountName", "cn", "description",
		"groupType", "mail", "memberOf"}
	OUAttributes       = []string{"distinguishedName", "objectGUID", "ou", "description", "gPLink"}
	ComputerAttributes = []string{"distinguishedName", "objectGUID", "objectSid", "sAMAccountName", "dNSHostName",
		"operatingSystem", "operatingSystemVersion", "userAccountControl", "lastLogonTimestamp", "memberOf", "description"}
)

// User is an AD user account.
type User struct {
	DN                string
	GUID              sid.GUID
	SID               sid.SID
	SAMAccountName    string
	UserPrincipalName string
	DisplayName       string
	GivenName         string
	Surname           string
	Mail              string
	Description       string
	Department        string
	Title             string
	TelephoneNumber   string
	Mobile            string
	HomePhone         string
	Office            string // physicalDeliveryOfficeName
	Company           string
	StreetAddress     string
	City              string // l
	State             string // st
	PostalCode        string
	HomePage          string // wWWHomePage
	// UAC is the stored userAccountControl; ComputedUAC adds the computed
	// LOCKOUT and PASSWORD_EXPIRED bits (msDS-User-Account-Control-Computed).
	UAC            UAC
	ComputedUAC    UAC
	PwdLastSet     FileTime
	LockoutTime    FileTime
	AccountExpires FileTime
	LastLogon      FileTime
	MemberOf       []string
	PrimaryGroupID uint32
	// PasswordExpiry is msDS-UserPasswordExpiryTimeComputed, read only with
	// UserExpiryAttributes; Never when the password does not expire.
	PasswordExpiry FileTime
	// BadPwdCount and BadPasswordTime are per DC (not replicated).
	BadPwdCount     int
	BadPasswordTime FileTime
	// WhenCreated is the generalized time the account was created.
	WhenCreated time.Time
}

// PasswordExpires returns when the password expires; zero when it never
// does or the attribute was not read.
func (u User) PasswordExpires() time.Time {
	if u.PasswordExpiry <= 0 || u.PasswordExpiry == Never {
		return time.Time{}
	}
	return u.PasswordExpiry.Time()
}

// Enabled reports whether the account is not disabled.
func (u User) Enabled() bool { return !u.UAC.Has(UACAccountDisable) }

// Locked reports whether the account is currently locked out.
func (u User) Locked() bool { return u.ComputedUAC.Has(UACLockout) }

// PasswordExpired reports whether the password has expired (computed).
func (u User) PasswordExpired() bool { return u.ComputedUAC.Has(UACPasswordExpired) }

// MustChangePassword reports pwdLastSet = 0.
func (u User) MustChangePassword() bool { return u.PwdLastSet == 0 }

// AccountExpired reports whether accountExpires is in the past.
func (u User) AccountExpired(now time.Time) bool {
	t := u.AccountExpires.Time()
	return !t.IsZero() && t.Before(now)
}

// Group is an AD group.
type Group struct {
	DN             string
	GUID           sid.GUID
	SID            sid.SID
	SAMAccountName string
	Name           string
	Description    string
	Mail           string
	Type           GroupType
	MemberOf       []string
}

// GroupType is the groupType attribute.
type GroupType int32

// groupType flags.
const (
	GroupTypeGlobal      GroupType = 0x2
	GroupTypeDomainLocal GroupType = 0x4
	GroupTypeUniversal   GroupType = 0x8
	GroupTypeSecurity    GroupType = -0x80000000
)

// Security reports a security (not distribution) group.
func (g GroupType) Security() bool { return g&GroupTypeSecurity != 0 }

// Scope returns "global", "domainlocal", "universal" or "builtin".
func (g GroupType) Scope() string {
	switch {
	case g&GroupTypeGlobal != 0:
		return "global"
	case g&GroupTypeDomainLocal != 0:
		return "domainlocal"
	case g&GroupTypeUniversal != 0:
		return "universal"
	default:
		return "builtin"
	}
}

// OU is an organizational unit.
type OU struct {
	DN          string
	GUID        sid.GUID
	Name        string
	Description string
	GPLink      string
}

// Computer is a computer account.
type Computer struct {
	DN                     string
	GUID                   sid.GUID
	SID                    sid.SID
	SAMAccountName         string
	DNSHostName            string
	OperatingSystem        string
	OperatingSystemVersion string
	Description            string
	UAC                    UAC
	LastLogon              FileTime
	MemberOf               []string
}

// Enabled reports whether the computer account is not disabled.
func (c Computer) Enabled() bool { return !c.UAC.Has(UACAccountDisable) }

// IsDomainController reports a DC's account (SERVER_TRUST_ACCOUNT): callers
// must not disable, move or delete it through generic account management.
func (c Computer) IsDomainController() bool { return c.UAC.Has(UACServerTrustAccount) }

func attrInt64(e *ldap.Entry, name string) int64 {
	v, _ := strconv.ParseInt(e.GetAttributeValue(name), 10, 64)
	return v
}

func attrSID(e *ldap.Entry) sid.SID {
	s, _ := sid.FromBytes(e.GetRawAttributeValue("objectSid"))
	return s
}

func attrGUID(e *ldap.Entry) sid.GUID {
	g, _ := sid.GUIDFromBytes(e.GetRawAttributeValue("objectGUID"))
	return g
}

// UserFromEntry decodes an entry read with UserAttributes.
func UserFromEntry(e *ldap.Entry) User {
	return User{
		DN:                e.DN,
		GUID:              attrGUID(e),
		SID:               attrSID(e),
		SAMAccountName:    e.GetAttributeValue("sAMAccountName"),
		UserPrincipalName: e.GetAttributeValue("userPrincipalName"),
		DisplayName:       e.GetAttributeValue("displayName"),
		GivenName:         e.GetAttributeValue("givenName"),
		Surname:           e.GetAttributeValue("sn"),
		Mail:              e.GetAttributeValue("mail"),
		Description:       e.GetAttributeValue("description"),
		Department:        e.GetAttributeValue("department"),
		Title:             e.GetAttributeValue("title"),
		TelephoneNumber:   e.GetAttributeValue("telephoneNumber"),
		Mobile:            e.GetAttributeValue("mobile"),
		HomePhone:         e.GetAttributeValue("homePhone"),
		Office:            e.GetAttributeValue("physicalDeliveryOfficeName"),
		Company:           e.GetAttributeValue("company"),
		StreetAddress:     e.GetAttributeValue("streetAddress"),
		City:              e.GetAttributeValue("l"),
		State:             e.GetAttributeValue("st"),
		PostalCode:        e.GetAttributeValue("postalCode"),
		HomePage:          e.GetAttributeValue("wWWHomePage"),
		UAC:               UAC(uint32(attrInt64(e, "userAccountControl"))),
		ComputedUAC:       UAC(uint32(attrInt64(e, "msDS-User-Account-Control-Computed"))),
		PwdLastSet:        FileTime(attrInt64(e, "pwdLastSet")),
		LockoutTime:       FileTime(attrInt64(e, "lockoutTime")),
		AccountExpires:    FileTime(attrInt64(e, "accountExpires")),
		LastLogon:         FileTime(attrInt64(e, "lastLogonTimestamp")),
		MemberOf:          e.GetAttributeValues("memberOf"),
		PrimaryGroupID:    uint32(attrInt64(e, "primaryGroupID")),
		PasswordExpiry:    FileTime(attrInt64(e, "msDS-UserPasswordExpiryTimeComputed")),
		BadPwdCount:       int(attrInt64(e, "badPwdCount")),
		BadPasswordTime:   FileTime(attrInt64(e, "badPasswordTime")),
		WhenCreated:       generalizedTime(e.GetAttributeValue("whenCreated")),
	}
}

// generalizedTime parses an LDAP GeneralizedTime ("20261002021448.0Z").
func generalizedTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	// AD writes "YYYYMMDDHHMMSS.0Z"; drop the fraction and parse the rest.
	if i := strings.IndexByte(v, '.'); i > 0 {
		v = v[:i] + "Z"
	}
	t, err := time.Parse("20060102150405Z", v)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// GroupFromEntry decodes an entry read with GroupAttributes.
func GroupFromEntry(e *ldap.Entry) Group {
	return Group{
		DN:             e.DN,
		GUID:           attrGUID(e),
		SID:            attrSID(e),
		SAMAccountName: e.GetAttributeValue("sAMAccountName"),
		Name:           e.GetAttributeValue("cn"),
		Description:    e.GetAttributeValue("description"),
		Mail:           e.GetAttributeValue("mail"),
		Type:           GroupType(int32(attrInt64(e, "groupType"))),
		MemberOf:       e.GetAttributeValues("memberOf"),
	}
}

// OUFromEntry decodes an entry read with OUAttributes.
func OUFromEntry(e *ldap.Entry) OU {
	return OU{DN: e.DN, GUID: attrGUID(e), Name: e.GetAttributeValue("ou"),
		Description: e.GetAttributeValue("description"), GPLink: e.GetAttributeValue("gPLink")}
}

// ComputerFromEntry decodes an entry read with ComputerAttributes.
func ComputerFromEntry(e *ldap.Entry) Computer {
	return Computer{
		DN:                     e.DN,
		GUID:                   attrGUID(e),
		SID:                    attrSID(e),
		SAMAccountName:         e.GetAttributeValue("sAMAccountName"),
		DNSHostName:            e.GetAttributeValue("dNSHostName"),
		OperatingSystem:        e.GetAttributeValue("operatingSystem"),
		OperatingSystemVersion: e.GetAttributeValue("operatingSystemVersion"),
		Description:            e.GetAttributeValue("description"),
		UAC:                    UAC(uint32(attrInt64(e, "userAccountControl"))),
		LastLogon:              FileTime(attrInt64(e, "lastLogonTimestamp")),
		MemberOf:               e.GetAttributeValues("memberOf"),
	}
}
