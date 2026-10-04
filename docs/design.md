# ad: design

`ad` is the Go library every Samba Conductor component uses to reach a
Samba (or Windows) Active Directory domain. It signs users in with
Kerberos, opens LDAPS connections bound with the signed-in user's own
ticket, reads the directory with paged and escaped searches, describes
every write as an operation with an exact preview, and runs the few
`samba-tool` commands LDAP cannot replace through typed, validated
operations. It also defines the protocol between conductor and its
privileged helper. It is a standalone module
(`github.com/openbasalt/samba-conductor-ad`, package `ad`) so tools
outside the web stack can use it too. The cross-cutting design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md#the-ad-library).

## API shape

- No global state. Everything starts from a `Config` value (realm, DC
  names or discovery, pinned CA pool, resolver, timeouts); it holds no
  credentials.
- Every network call takes a `context.Context`; cancelling it closes the
  connection or abandons the paged search in progress.
- Typed errors. Sign-in and bind refusals are `*AuthError` values with a
  `Reason` and sentinels for `errors.Is` (`ErrInvalidCredentials`,
  `ErrPasswordExpired`, `ErrPasswordMustChange`, `ErrAccountLocked`,
  `ErrAccountDisabled`, `ErrAccountExpired`, `ErrClockSkew`, and more).
  Writes fail with `ErrAccessDenied`, `ErrPasswordPolicy`, `ErrConflict`,
  `ErrProtectedObject` and similar sentinels. A connection that could not
  reach any DC returns a `*FailoverError` listing every attempt.
- Sub-packages: `escape` (filters and DNs), `sid` (SIDs, GUIDs,
  well-known RIDs), `sambatool` (typed samba-tool operations), `helper`
  (privileged helper protocol).

## Sign-in and authentication

### Kerberos first

`SignIn(ctx, cfg, username, password)` performs one AS exchange and
returns a `Session` holding only the TGT and its session key, built from
an in-memory credential cache. The password is used for that exchange and
never enters a long-lived client; when the TGT expires the user signs in
again. The library does its own AS exchange (instead of the Kerberos
library's client) to read the KDC error data (NTSTATUS in `e-data`) and to
keep the password out of any object that outlives the call.

- Kerberos is TCP only, AES only (no RC4 or DES), with no DNS realm
  guessing.
- The UPN suffix must be the realm. Alternative UPN suffixes
  (NT-ENTERPRISE principals) are not implemented.
- A `Session` sends its TGS requests to the KDC that issued its TGT first,
  then to the others in configured order. The Kerberos library alone
  shuffles KDCs per request, which made a request right after a password
  change or a user creation reach a DC that had not replicated it yet.
- `Session.WriteCCache(path)` writes the TGT to a standard credential
  cache file (0600) so samba-tool can act as the user. Absent optional
  ticket times are written as the auth time, not as zero, which MIT and
  Heimdal clients would read as a ticket not yet valid.

### Refusals and sub-codes

Both Kerberos and simple bind classify refusals the same way:

| AD sub-code / KDC result | Reason | Password proven right |
|---|---|---|
| 52e, 525, generic 49, preauth failed, unknown principal | invalid credentials | no |
| 532 / key expired + `STATUS_PASSWORD_EXPIRED` | password expired | yes |
| 773 / key expired + `STATUS_PASSWORD_MUST_CHANGE` | must change | yes |
| 775 / client revoked + `STATUS_ACCOUNT_LOCKED_OUT` | locked | no |
| 533 / client revoked + `STATUS_ACCOUNT_DISABLED` | disabled | no |
| 701 / client revoked + `STATUS_ACCOUNT_EXPIRED` | account expired | no |

A generic result 49 is never read as "maybe expired". Samba's KDC returns
`KDC_ERR_KEY_EXPIRED` before it validates the password, so a wrong
password gets it too. The library sets `PasswordVerified()` only after a
second AS exchange for `kadmin/changepw` (which accepts expired passwords)
succeeds; otherwise the result is "invalid credentials".

### Password change versus reset

- `ChangePasswordKerberos` changes the user's own password with kpasswd
  (RFC 3244, protocol version 1, change own password). It needs no LDAP
  bind, which users whose password expired or must change cannot do. The
  Kerberos library's kpasswd sends the set-password form with the caller
  as target, which Samba refuses for ordinary users, so the library builds
  its own request.
- `ChangePassword` (self, LDAP delete of the old `unicodePwd` plus add of
  the new one) and `ResetPassword` (administrator, replace, optionally
  forcing a change at next logon) are separate operations.

### Simple bind fallback

`SimpleAuth(username, password)` binds over TLS with the password. It is
an explicit choice of the caller, used only when Kerberos is unavailable.

## LDAPS, CA pinning and channel bindings

- LDAPS only, TLS 1.2 or newer. `Config.RootCAs` is required and is the
  only trust anchor (normally the domain CA); the system pool is never
  used. The only way around verification is the deliberately named
  `Config.InsecureSkipTLSVerifyForTestsOnly`.
- `KerberosAuth(session)` binds with SASL/GSSAPI using the session's
  ticket. The AP-REQ carries RFC 5929 `tls-server-end-point` channel
  bindings (the hash of the DC's certificate), tying the Kerberos
  authenticator to this TLS connection so it cannot be relayed through a
  TLS-terminating man in the middle. Current Samba requires these
  bindings for GSSAPI over LDAPS (4.22 refuses a bind without them with
  `80090346`).
- The GSSAPI client builds its own AP-REQ to add the bindings. It is
  adapted from go-ldap's GSSAPI client (MIT, see NOTICE).
- Wrap tokens (RFC 4121): the acceptor's token may be rotated right by
  RRC bytes. Heimdal (Samba on Debian and Ubuntu) rotates by the checksum
  length; MIT Kerberos (Samba on Fedora) does not rotate. The library
  undoes any rotation before splitting payload and checksum, so both
  verify. Lengths read from the wire are bounds-checked.
- No SASL security layer (sign or seal) is negotiated: integrity and
  confidentiality come from TLS. Samba 4.19 refuses GSSAPI over LDAPS
  without one unless the DC sets
  `ldap server require strong auth = allow_sasl_over_tls`; 4.20 and newer
  accept it.

## DC discovery and failover

- DCs come from DNS SRV records (`_ldap._tcp.dc._msdcs.<realm>`), ordered
  by priority and weight, with `Config.Preferred` hosts (normally the
  local DC) first. `Config.DCs` replaces discovery with a fixed list.
- `NewDNSResolver` queries the given DNS servers over TCP, so a
  dead server is detected at connect time and the next one is tried.
- `Connect` fails over to the next DC only on connectivity errors (dial,
  TLS handshake, reset). A refused credential is returned at once and
  never retried on another DC or KDC, so a wrong password is not sprayed
  across DCs and does not multiply bad-password counts. A certificate that
  does not chain to the pinned CA fails that DC only.
- Read-your-writes: an object created on one DC is unknown to the others
  until replication. Callers put the DC that made a write first in
  `Preferred` for follow-up calls.

## LDAP hygiene

- Every list is a paged search (RFC 2696) streamed through a Go iterator
  (`Conn.Search`, `Conn.Users`, and similar). Breaking out of the loop
  abandons the server-side paged result. Samba does not truncate unpaged
  searches at 1,000 entries the way Windows does, but the library pages
  anyway.
- Sorted pages for user interfaces: `SearchRequest.SortBy` adds an RFC
  2891 sort control, combined with paging, and `Conn.SearchWindow` returns
  one page of a sorted search. Samba reads the reverse flag only when
  encoded as 0xFF, so the library encodes the control itself.
- Ranged retrieval: `Conn.RangedValues` reads every value of a large
  multi-valued attribute (`member;range=0-1499` and onwards), so big
  groups are complete.
- Escaping: filters are built only with `escape` builders (`Eq`,
  `Prefix`, `Contains`, `And`, `Or`, `Not`, `BitAnd`, `InChain`,
  `EqBytes`), which apply RFC 4515 escaping. `escape.RawFilter` exists for
  trusted constants such as `(objectClass=*)` and must never hold input.
  DNs are escaped per RFC 4514 and normalized with `escape.NormalizeDN`.
  Both are fuzz-tested.
- Authorization is by SID, never by name or DN substring:
  `Conn.IsMemberOfSID` compares against the user's `tokenGroups` computed
  by the DC (nested membership, primary group included), and
  `Conn.WellKnownGroupSID` resolves well-known RIDs (Domain Admins = 512).

## Typed model

`User`, `Group`, `OU`, `Computer` and `DC` carry the common attributes
with decoded values: `userAccountControl` flags, the constructed
`msDS-User-Account-Control-Computed` (real lockout state), `pwdLastSet`,
`lockoutTime`, `objectSid` as a string, `objectGUID`. Further models cover
AD-integrated DNS (zones, nodes, `dnsRecord` values encoded and decoded
per MS-DNSP), GPOs and their links (`gPLink`, `gPOptions`), the domain
password policy, fine-grained password policies (PSOs) and the effective
policy of a user (`msDS-ResultantPSO`, computed expiry time).

## Writes: preview, then apply

Every write is an `Operation` built by a constructor (`CreateUser`,
`UpdateUser`, `SetUserEnabled`, `ResetPassword`, `MoveObject`,
`AddGroupMember`, `CreateOU`, `DeleteObject`, DNS, GPO link and policy
operations, and more). `op.Preview()` returns the exact LDAP changes as
LDIF with secrets redacted; `conn.Apply(ctx, op)` applies that same
object. Callers show the preview, ask for confirmation, then apply,
without rebuilding anything.

Preconditions and optimistic checks:

- A write computed from a read (enable or disable from the
  `userAccountControl` read, a `gPLink` change) carries a precondition:
  an RFC 4528 assertion control, honoured by Windows AD, plus a re-read of
  the precondition right before the write, because Samba accepts the
  control without evaluating it. A stale read yields `ErrConflict`. On
  Samba a narrow race between the re-read and the write remains.
- DNS record updates and deletes remove the old value by its exact bytes,
  so a concurrent change conflicts instead of being overwritten. Every
  record change increments the zone's SOA serial the same way. `DNSPolicy`
  refuses the AD zones and the records AD manages (apex SOA and NS,
  locator names starting with `_`, DC host records, the whole `_msdcs`
  zone) with `ErrProtectedObject`; DCs are discovered from computer
  accounts, never named in code.
- `DeleteObject` is never recursive (DNS zone deletion is a separate,
  explicit tree delete of a non-AD zone). `SetComputerEnabled` refuses
  domain controllers.
- Per-DC writes: `UnlockUserOnDCs` plus `ApplyOnDCs` write
  `lockoutTime = 0` on every writable DC with a connection bound as the
  user, reporting each DC, because lockout state replicates with a delay.

## samba-tool operations

Package `sambatool` covers what LDAP cannot do (GPO creation and deletion,
which also write SYSVOL; domain levels; FSMO roles; replication status;
online backup and restore; the DNS RPC path).

- An operation is a Go type whose fields are validated before any command
  is built. There is no way to pass free-form arguments.
- User-supplied values are positional arguments after `--`, and a value
  starting with `-` is rejected anyway.
- Secrets never go into argv. `Password` writes the password to a pipe
  inherited by the child and announced with `PASSWD_FD`;
  `KerberosCCache` passes a credential cache path; `LocalSystem` runs as
  root against the local database (the helper's case).
- `sambatool.Preview(runner, op)` returns the exact command line that
  `Run` executes, which callers show before confirming. Output is parsed
  into structs; raw output is not meant for end users.
- `samba-tool gpo` accepts only `-H`, so the package builds `-H<url>` from
  a validated LDAP URL.

## Helper protocol

Package `helper` defines the protocol between conductor (unprivileged) and
conductor-helper (root, local only); the helper itself lives in the
conductor repository.

- Transport: a Unix stream socket; the server checks the peer with
  `SO_PEERCRED`. One JSON object per line, at most 64 KiB.
- A `Request` carries a protocol version, an ID, an allowlisted operation
  name, the caller (AD user, SID, session ID, source address) and typed
  parameters. Parameters and results are decoded strictly (unknown fields
  rejected) and validated before the helper acts.
- The allowlist names every operation (ping, domain level, FSMO roles, DC
  list, replication status, service status, online backup, backup status,
  trigger and policy); the helper enables a subset per peer. Anything else
  is refused with `not_allowed`.
- Requests never carry passwords. The backup archive format and the
  backup policy, status and request types shared by conductor,
  conductor-helper and conductor-backup are also defined here.

## Security notes

- The library acts with whatever identity it is given. In conductor that
  is the signed-in user's ticket, so AD's own ACLs decide every read and
  write.
- Passwords live only for the call that needs them; previews redact
  `unicodePwd`.
- Clock skew is reported as its own reason so callers can point at time
  synchronization instead of credentials.
- Tests: unit tests (escaping fuzzers, sub-code mapping, SID decoding,
  previews, wrap tokens) and integration tests tagged `lab` against a
  two-DC Samba domain (both bind paths, paging over 2,500 users, every
  sub-code, change versus reset, DC failover, DNS, GPO and policy writes).

## Decisions

- Kerberos library: `github.com/go-krb5/krb5`, a maintained fork of
  `jcmturner/gokrb5`, whose original is unmaintained. LDAP:
  `github.com/go-ldap/ldap/v3`.
- Own AS exchange, GSSAPI AP-REQ and kpasswd request: needed to read the
  KDC's NTSTATUS, to add channel bindings, and because Samba refuses the
  set-password form of kpasswd for ordinary users.
- Channel bindings always sent: Samba requires them for GSSAPI over LDAPS.
- Password verified with a `kadmin/changepw` exchange before reporting
  "expired": Samba's KDC reports expiry before checking the password, and
  treating an unverified "expired" as proof of the password would let a
  wrong password reach a change page.
- KDC order pinned per session: the shuffling of the Kerberos library
  produced failures after password changes and creations on another DC.
- Assertion control plus re-read for optimistic concurrency: Windows
  honours RFC 4528, Samba does not, and both should refuse a stale write
  where they can.
- DNS over LDAP on the DNS application partitions rather than DNS RPC:
  the same identity and ACLs as every other write, exact LDIF previews,
  paged reads and no subprocess. Samba's DNS server reads the database on
  every query, so changes answer at once.
- Paging always, even where Samba would return everything: the same code
  then works against Windows AD and keeps memory bounded.
- A separate module whose path is its repository path, so `go get` and
  `go install` resolve it.
