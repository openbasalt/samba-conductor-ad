// Package ad accesses a Samba (or Windows) Active Directory domain with the
// signed-in user's own identity.
//
// Sign-in is Kerberos first: [SignIn] performs one AS exchange with the
// user's password and returns a [Session] that keeps only the ticket. LDAP
// connections are LDAPS with the domain CA pinned ([Config.RootCAs]) and are
// bound with SASL/GSSAPI using that ticket and TLS channel bindings
// ([KerberosAuth]); an LDAP simple bind over TLS is the explicit fallback
// ([SimpleAuth]). Refusals are classified into [AuthError] values from the AD
// bind sub-codes (52e, 532, 773, 775, 533, 701) or the KDC errors; only
// [AuthError.PasswordVerified] proves the password was right.
//
// DCs are discovered through DNS SRV records, preferred hosts first, and
// [Connect] fails over to the next DC on connectivity errors only (never on a
// wrong password). Every list is a paged search (RFC 2696) streamed through an
// iterator ([Conn.Search], [Conn.Users], …); filters and DNs are built with
// the escape package; group membership checks compare SIDs computed by the DC
// ([Conn.IsMemberOfSID]).
//
// Writes are [Operation] values: build one (CreateUser, ResetPassword,
// ChangePassword, AddGroupMember, …), show its [Preview] (the exact LDAP
// changes, secrets redacted), then [Conn.Apply] it.
//
// Sub-packages: escape (RFC 4515/4514), sid (SIDs, GUIDs, well-known RIDs),
// sambatool (typed samba-tool operations), helper (privileged helper
// protocol types).
package ad
