# ad: guidelines

Go library for Samba Active Directory access: LDAP with paged results and RFC 4515/4514 escaping, Kerberos sign-in (GSSAPI), typed samba-tool operations with an exact command preview. Used by conductor and, later, tui-dc.

- Read `../CLAUDE.md` (family rules) and [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
