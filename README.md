# ad

Go library for Samba Active Directory access, used by Samba Conductor v2 and
later by `tui-dc`. Pure library: no global state, `context.Context` on every
network call, typed errors. Design: `../planning/docs/architecture.md` (§4, §5,
§8) and `../planning/docs/p0-spec.md`.

Module `github.com/openbasalt/samba-conductor-ad` (the repository path, so
`go get` resolves it), package `ad`; import it with an explicit name:

```go
import ad "github.com/openbasalt/samba-conductor-ad"
```

Go 1.27. While the repository is private, `go get` needs
`GOPRIVATE=github.com/openbasalt/*` and git credentials for GitHub (see
CONTRIBUTING.md).

| Package | What |
|---|---|
| `ad` | Connection (LDAPS, CA pinning, SRV discovery, failover), Kerberos sign-in and SASL/GSSAPI bind, simple-bind fallback, AD bind sub-codes, paged search iterator, typed models, operations with Preview then Apply, password change vs reset |
| `ad/escape` | RFC 4515 filter builder and RFC 4514 DN escaping (fuzz-tested); `RawFilter` only for trusted constants |
| `ad/sid` | SID and GUID decoding/formatting, well-known RIDs (Domain Admins = 512) |
| `ad/sambatool` | Typed samba-tool operations: validated fields to argv, `--` before user values, no secrets in argv, parsed output, exact command preview |
| `ad/helper` | Protocol of the privileged helper (Unix socket, allowlisted typed requests, result types, a `Call` client); the helper itself is built in `conductor` |

## Usage

### Sign in with Kerberos and connect

```go
pemCA, _ := os.ReadFile("/etc/conductor/domain-ca.pem")
pool, err := ad.CertPoolFromPEM(pemCA) // pin the domain CA, nothing else
cfg := ad.Config{
    Realm:     "LAB.CONDUCTOR.TEST",
    RootCAs:   pool,
    Preferred: []string{"dc1.lab.conductor.test"}, // e.g. the local DC
    // Resolver: ad.NewDNSResolver("10.93.0.10", "10.93.0.11") when the
    // host's resolver is not the domain DNS.
}

session, err := ad.SignIn(ctx, cfg, username, password) // password used once
if err != nil {
    var ae *ad.AuthError
    if errors.As(err, &ae) && ae.PasswordVerified() {
        // Expired or must-change: the password was right; offer a change
        // with ad.ChangePasswordKerberos.
    }
    // Anything else: "wrong username or password" to the user; ae.Code to logs.
    return err
}
defer session.Close()

conn, err := ad.Connect(ctx, cfg, ad.KerberosAuth(session)) // LDAPS + GSSAPI
if err != nil {
    return err
}
defer conn.Close()
```

`ad.SimpleAuth(username, password)` is the explicit fallback (LDAP simple bind
over TLS). Both paths classify refusals identically:

| AD sub-code / KDC | `Reason` | `PasswordVerified()` |
|---|---|---|
| 52e, 525, generic 49, `KDC_ERR_PREAUTH_FAILED`, `C_PRINCIPAL_UNKNOWN` | `ReasonInvalidCredentials` | false |
| 532 / `KEY_EXPIRED` + `STATUS_PASSWORD_EXPIRED` | `ReasonPasswordExpired` | true |
| 773 / `KEY_EXPIRED` + `STATUS_PASSWORD_MUST_CHANGE` | `ReasonPasswordMustChange` | true |
| 775 / `CLIENT_REVOKED` + `STATUS_ACCOUNT_LOCKED_OUT` | `ReasonAccountLocked` | false |
| 533 / `CLIENT_REVOKED` + `STATUS_ACCOUNT_DISABLED` | `ReasonAccountDisabled` | false |
| 701 / `CLIENT_REVOKED` + `STATUS_ACCOUNT_EXPIRED` | `ReasonAccountExpired` | false |

A generic result 49 is never read as "maybe expired". Samba's KDC reports an
expired password before it checks the password, so for Kerberos the library
confirms the password with an AS exchange for `kadmin/changepw` (which accepts
expired passwords) before setting `PasswordVerified`.

### Search (always paged)

```go
for u, err := range conn.Users(ctx, "OU=People,OU=Lab,"+conn.BaseDN(),
    escape.And(escape.Prefix("sAMAccountName", input), escape.Not(escape.BitAnd("userAccountControl", 2)))) {
    if err != nil { return err }
    fmt.Println(u.SAMAccountName, u.Enabled(), u.Locked(), u.SID)
}
```

`SearchRequest.SortBy` adds an RFC 2891 sort (works together with paging on
Samba; the control is encoded by the library because go-ldap's reverse flag
is ignored by Samba). `Conn.Count` counts without attributes and
`Conn.SearchWindow(req, skip, n)` returns one page of a sorted search for
page-numbered UIs.

Filters only come from the `escape` builders (`Eq`, `Prefix`, `Contains`,
`And`, `Or`, `Not`, `BitAnd`, `InChain`, `EqBytes`…). `escape.RawFilter` exists
for constants such as `"(objectClass=*)"` and must never hold user input.
Breaking out of the loop abandons the server-side paged result.

### Authorization by SID

```go
da, _ := conn.WellKnownGroupSID(ctx, sid.RIDDomainAdmins)
isAdmin, _ := conn.IsMemberOfSID(ctx, user.DN, da) // tokenGroups: nested, by SID
```

### Writes: Preview, then Apply

```go
op, err := ad.ResetPassword(user.DN, newPassword, true /* must change */)
fmt.Println(op.Preview()) // LDIF, unicodePwd shown as <redacted>
// ... user confirms ...
err = conn.Apply(ctx, op) // errors.Is: ErrAccessDenied, ErrPasswordPolicy, ErrConflict, ...
```

Operations: `CreateUser`, `UpdateUser`, `SetUserEnabled`,
`SetComputerEnabled` (refuses domain controllers), `UnlockUser`,
`ResetPassword` (admin), `ChangePassword` (self, LDAP delete+add of
`unicodePwd`), `MoveObject`, `RenameObject`, `AddGroupMember`,
`RemoveGroupMember`, `CreateGroup`, `CreateOU`, `DeleteObject` (never
recursive). `UserUpdateAttributes()` lists what `UpdateUser` can write; the
lab test `TestLabSelfWritableAttributes` pins which of them Samba lets users
write on themselves (telephoneNumber, mobile, homePhone,
physicalDeliveryOfficeName, streetAddress, l, st, postalCode, wWWHomePage).
`ChangePasswordKerberos` (kpasswd, RFC 3244 version 1) changes a password
without an LDAP bind, which users who must change or whose password expired
cannot do.

`SetUserEnabled` is computed from the user as read and carries a precondition
on the old `userAccountControl` (an RFC 4528 assertion plus a re-read before
the write, since Samba ignores the assertion control): a stale read yields
`ErrConflict` instead of overwriting a concurrent change.

### DNS, Group Policy, password policies (P2)

```go
zones, _ := conn.DNSZones(ctx)                 // DomainDnsZones, ForestDnsZones, legacy
pol, _ := conn.DNSPolicy(ctx)                  // AD zones and records, DCs discovered
z, _ := conn.DNSZoneByName(ctx, "apps.example.com")
apex, _ := conn.DNSNodeByName(ctx, z, "@")
node, _ := conn.DNSNodeByName(ctx, z, "www")
rec, _ := ad.NewDNSRecord(ad.DNSTypeA, "192.0.2.10", 3600)
op, err := ad.AddDNSRecord(z, pol, apex, node, rec) // + SOA serial bump
```

AD-integrated DNS is read and written over LDAP (dnsZone/dnsNode objects,
binary `dnsRecord` values encoded per MS-DNSP) with the user's own
credentials; Samba's DNS server reads the database on every query, so a
change answers at once. `UpdateDNSRecord`/`DeleteDNSRecord` delete the old
value by its exact bytes (a concurrent change is `ErrConflict`), every change
increments the zone's SOA serial, and `DNSPolicy` refuses the AD zones and
the records AD manages (apex SOA/NS, `_` locator names, DC host records, the
whole `_msdcs` zone) with `ErrProtectedObject`. `CreateDNSZone` writes the
zone and its apex (SOA + NS of the DC in use); `DeleteDNSZone` is a tree
delete of a non-AD zone. Previews show the decoded record next to its
base64 value.

Group Policy: `GPOs`, `GPOByID`, `GPContainers` (who links what),
`ChangeGPLink` (link, unlink, enable/disable, enforce, link order; the old
`gPLink` value is asserted) and `SetBlockInheritance`. GPO creation and
deletion also touch SYSVOL: `sambatool.GPOCreate` / `GPODelete`, run with
the user's ticket (`Session.WriteCCache` + `sambatool.KerberosCCache`).

Password policy: `DomainPasswordPolicy` / `UpdateDomainPasswordPolicy`,
`PSOs`, `CreatePSO`, `UpdatePSO`, `ApplyPSO` / `UnapplyPSO`, and
`EffectivePasswordPolicy` (msDS-ResultantPSO and the computed expiry time).
`DomainControllers` lists the DCs from their computer accounts (per-DC
attributes such as `badPwdCount` need a connection to each DC: set
`Config.DCs` to one host).

### samba-tool

```go
r := &sambatool.Runner{Credentials: sambatool.Password{Username: "admin", Password: pw}}
op := sambatool.DNSAddRecord{Server: "dc1.lab.conductor.test", Zone: "lab.conductor.test",
    Name: "www", Type: sambatool.DNSTypeA, Data: "10.0.0.5"}
cmdline, _ := sambatool.Preview(r, op)
// samba-tool dns add --use-kerberos=off -U admin -- dc1.lab.conductor.test lab.conductor.test www A 10.0.0.5
_, err := sambatool.Run(ctx, r, op)
```

The password goes to samba-tool through an inherited pipe (`PASSWD_FD`), never
argv; `KerberosCCache` passes a credential cache path; `LocalSystem` runs
against the local database (the helper's case). Every user value is
positional after `--` and may not start with `-`.

## Security notes

- TLS: LDAPS only, TLS 1.2+, CA pinning required; the only way around it is
  `Config.InsecureSkipTLSVerifyForTestsOnly`.
- GSSAPI binds carry RFC 5929 `tls-server-end-point` channel bindings (Samba
  4.22 rejects binds without them with `80090346`).
- Kerberos: TCP only, AES only (no RC4/DES), no DNS realm guessing. The
  `Session` holds a TGT and session key, built from an in-memory credential
  cache; the password never enters a long-lived client. When the TGT expires
  the user signs in again.
- Failover never retries a refused password on another DC or KDC.
- Read-your-writes: an object created on one DC is unknown to the other DCs
  (LDAP and KDC) until replication. Put the DC that performed the write first
  in `Config.Preferred` for follow-up calls. A `Session` sends its TGS
  requests to the KDC that issued its TGT first, then in the configured
  order (go-krb5 alone shuffles KDCs, which made a sign-in right after a
  kpasswd change fail on a DC that had not replicated it yet).

## Development

```sh
make test        # unit tests (race detector)
make check       # gofmt, go vet, staticcheck, govulncheck, tests
make fuzz        # escape/sid/sambatool/helper fuzzers (FUZZTIME=20s)
make lab-test    # integration tests against the lab
```

`make lab-test` (`scripts/lab-test.sh`) compiles the `lab`-tagged test
binaries here, copies them to the lab host and runs them there (the lab
network is only reachable from that host): the `ad` tests on the host, the
`sambatool` tests as root on dc1. Secrets stay on the lab host. The lab:
`../planning/docs/lab.md`. A full run: [`docs/usage-p0.md`](docs/usage-p0.md).

## Status

P0 complete (2026-10-01): all unit and lab tests pass. P1 extensions
(2026-10-02) for conductor: profile attributes, sorting/windows, rename,
computer enable/disable, FSMO/DC-list helper operations, KDC pinning for
TGS requests; lab-tested. P2 (2026-10-02): DNS zones and records over
LDAP, GPOs and links, domain and fine-grained password policies, effective
policy, DC list, ccache export for samba-tool; lab-tested
(`lab_p2_test.go`, `sambatool/lab_p2_test.go`). See
`../planning/docs/decisions.md` for the choices made and what is left for P1.

License: Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
