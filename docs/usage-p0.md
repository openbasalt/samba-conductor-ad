# P0 lab integration run

Transcript of `make lab-test` (`scripts/lab-test.sh`) against the
lab (`../../planning/docs/lab.md`), run on 2026-10-01 right after
`planning/lab/reset.sh` restored the `seeded` snapshot. No secrets appear: the
tests never log passwords, and the transcript was checked against the lab's
secrets file before committing.

What the run covers (spec `planning/docs/p0-spec.md` §2):

| Test | Proves |
|---|---|
| `TestLabDiscovery` | SRV discovery of both DCs and KDCs, preferred DC first |
| `TestLabKerberosSignIn` | TGT from a password, SASL/GSSAPI bind over LDAPS (with TLS channel bindings) |
| `TestLabSimpleBind` | Simple-bind fallback over TLS |
| `TestLabTLSPinning` | A CA other than the domain CA is refused on every DC |
| `TestLabSubCodesSimpleBind` / `TestLabSubCodesKerberos` | 52e/532/773/775/533/701 and their Kerberos equivalents; a wrong password is never reported as expired/must-change; `verified` only when the password was proven right |
| `TestLabPaging` | Server pages at 500; 2,500 users streamed; early break abandons the result set |
| `TestLabGroupsBySID` | 1,600-member group via ranged retrieval; nested membership and Domain Admins (RID 512) by SID |
| `TestLabEscapedNames` | DN and filter escaping with a CN full of special characters; an injection attempt matches nothing |
| `TestLabOperations` | Create OU/group/user, membership, disable/enable with a stale-read conflict, update, move, lock by bad binds and unlock; every write previewed |
| `TestLabPasswordChangeVsReset` | Self change (LDAP) with wrong old password / weak password / success; plain user cannot reset; helpdesk resets inside its OU but not a Domain Admin; must-change after reset; kpasswd change; kpasswd with wrong old password |
| `TestLabZFailover` | dc1 stopped: Kerberos and LDAP land on dc2 |
| `TestLabDomainLevel`, `TestLabReplication`, `TestLabDNSWithPasswordFD` (on dc1) | Typed samba-tool operations, exact command preview, password via `PASSWD_FD` |

```text
=== ad package (on the lab host, Go test binary)
    lab_test.go:101: DCs (dc2 preferred): [{Host:dc2.lab.conductor.test Priority:0 Weight:100} {Host:dc1.lab.conductor.test Priority:0 Weight:100}]
--- PASS: TestLabDiscovery (0.00s)
    lab_test.go:119: principal user0001@LAB.CONDUCTOR.TEST, TGT valid until 2026-10-02T12:41:36Z
    lab_test.go:129: GSSAPI bind on dc1.lab.conductor.test as "u:LAB\\user0001" (base DC=lab,DC=conductor,DC=test, functional level 7)
--- PASS: TestLabKerberosSignIn (0.28s)
    lab_test.go:146: simple bind over TLS on dc2.lab.conductor.test as "u:LAB\\user0001"
--- PASS: TestLabSimpleBind (0.19s)
    lab_test.go:164: unpinned CA refused: ad: no domain controller reachable (dc1.lab.conductor.test: ad: TLS certificate of dc1.lab.conductor.test rejected: tls: failed to verify certificate: x509: certificate signed by unknown authority; dc2.lab.conductor.test: ad: TLS certificate of dc2.lab.conductor.test rejected: tls: failed to verify certificate: x509: certificate signed by unknown authority)
--- PASS: TestLabTLSPinning (0.06s)
    lab_test.go:197: simple   user0002          wrong -> invalid credentials        code=52e  verified=false
    lab_test.go:197: simple   no.such.user      wrong -> invalid credentials        code=52e  verified=false
    lab_test.go:197: simple   must.change       right -> password must be changed   code=773  verified=true
    lab_test.go:197: simple   must.change       wrong -> invalid credentials        code=52e  verified=false
    lab_test.go:197: simple   expired.password  right -> password expired           code=532  verified=true
    lab_test.go:197: simple   expired.password  wrong -> invalid credentials        code=52e  verified=false
    lab_test.go:197: simple   locked.user       right -> account locked             code=775  verified=false
    lab_test.go:197: simple   disabled.user     right -> account disabled           code=533  verified=false
    lab_test.go:197: simple   expired.account   right -> account expired            code=701  verified=false
--- PASS: TestLabSubCodesSimpleBind (0.71s)
    lab_test.go:212: kerberos user0002          wrong -> invalid credentials        code=KDC_ERR_PREAUTH_FAILED verified=false
    lab_test.go:212: kerberos no.such.user      wrong -> invalid credentials        code=KDC_ERR_C_PRINCIPAL_UNKNOWN verified=false
    lab_test.go:212: kerberos must.change       right -> password must be changed   code=KDC_ERR_KEY_EXPIRED/0xC0000224 verified=true
    lab_test.go:212: kerberos must.change       wrong -> invalid credentials        code=KDC_ERR_PREAUTH_FAILED verified=false
    lab_test.go:212: kerberos expired.password  right -> password expired           code=KDC_ERR_KEY_EXPIRED/0xC0000071 verified=true
    lab_test.go:212: kerberos expired.password  wrong -> invalid credentials        code=KDC_ERR_PREAUTH_FAILED verified=false
    lab_test.go:212: kerberos locked.user       right -> account locked             code=KDC_ERR_CLIENT_REVOKED/0xC0000234 verified=false
    lab_test.go:212: kerberos disabled.user     right -> account disabled           code=KDC_ERR_CLIENT_REVOKED/0xC0000072 verified=false
    lab_test.go:212: kerberos expired.account   right -> account expired            code=KDC_ERR_CLIENT_REVOKED/0xC0000193 verified=false
--- PASS: TestLabSubCodesKerberos (1.02s)
    lab_test.go:240: first page: 500 entries, cookie 2 bytes
    lab_test.go:252: first: user2041 CN=User 2041,OU=Engineering,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test uac=NORMAL_ACCOUNT
    lab_test.go:256: paged search (page size 500): 2500 users in 4.588s
--- PASS: TestLabPaging (5.52s)
    lab_test.go:288: Big Group: 1600 members (ranged retrieval)
    lab_test.go:312: All Staff transitive user members (LDAP_MATCHING_RULE_IN_CHAIN): 2500
    lab_test.go:324: Domain Admins S-1-5-21-2731809216-992630030-2226254955-512: lab.admin=true user0001=false
--- PASS: TestLabGroupsBySID (3.63s)
    lab_test.go:337: escape.test DN: CN=Escape\, Test \#1 \+ \"q\" \<x\>\3B \\ \3D,OU=Special,OU=Lab,DC=lab,DC=conductor,DC=test
--- PASS: TestLabEscapedNames (0.21s)
    lab_test.go:386: preview:
        # create OU Ops Test 3fa6ab
        dn: OU=Ops Test 3fa6ab,OU=Lab,DC=lab,DC=conductor,DC=test
        changetype: add
        objectClass: top
        objectClass: organizationalUnit
        ou: Ops Test 3fa6ab
        description: integration test
    lab_test.go:406: preview:
        # create user ops.u3fa6ab (NORMAL_ACCOUNT)
        dn: CN=Ops\, User 3fa6ab,OU=Ops Test 3fa6ab,OU=Lab,DC=lab,DC=conductor,DC=test
        changetype: add
        objectClass: top
        objectClass: person
        objectClass: organizationalPerson
        objectClass: user
        cn: Ops, User 3fa6ab
        sAMAccountName: ops.u3fa6ab
        userPrincipalName: ops.u3fa6ab@lab.conductor.test
        displayName: Ops User
        unicodePwd: <redacted>
        userAccountControl: 512
    lab_test.go:428: preview:
        # disable user ops.u3fa6ab (NORMAL_ACCOUNT -> ACCOUNTDISABLE|NORMAL_ACCOUNT)
        dn: CN=Ops\, User 3fa6ab,OU=Ops Test 3fa6ab,OU=Lab,DC=lab,DC=conductor,DC=test
        # only if the entry still matches (userAccountControl=512)
        control: 1.3.6.1.1.12 true
        changetype: modify
        replace: userAccountControl
        userAccountControl: 514
        -
    lab_test.go:436: change computed from a stale read: ad: modify CN=Ops\, User 3fa6ab,OU=Ops Test 3fa6ab,OU=Lab,DC=lab,DC=conductor,DC=test: ad: object changed since it was read: precondition no longer holds
    lab_test.go:453: preview:
        # move object
        dn: CN=Ops\, User 3fa6ab,OU=Ops Test 3fa6ab,OU=Lab,DC=lab,DC=conductor,DC=test
        changetype: moddn
        newrdn: CN=Ops\, User 3fa6ab
        deleteoldrdn: 1
        newsuperior: OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test
    lab_test.go:475: after 11 bad binds: locked=true lockoutTime=2026-10-02T02:41:49Z
--- PASS: TestLabOperations (1.23s)
    lab_test.go:509: change with wrong old password: ad: modify CN=Temp tmp.d655fd,OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test: ad: old password is wrong: LDAP Result Code 19 "Constraint Violation": 00000056: Constraint violation - check_password_restrictions: The old password specified doesn't match!
    lab_test.go:515: change to a weak password: ad: modify CN=Temp tmp.d655fd,OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test: ad: password does not satisfy the password policy: LDAP Result Code 19 "Constraint Violation": 0000052D: Constraint violation - check_password_restrictions: the password is too short. It should be equal to or longer than 7 characters!
    lab_test.go:521: preview:
        # change own password
        dn: CN=Temp tmp.d655fd,OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test
        changetype: modify
        delete: unicodePwd
        unicodePwd: <redacted>
        -
        add: unicodePwd
        unicodePwd: <redacted>
        -
    lab_test.go:535: plain user resetting another user: ad: modify CN=Temp tmp.ec205d,OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test: ad: access denied: LDAP Result Code 50 "Insufficient Access Rights": error in module acl: insufficient access rights during LDB_MODIFY (50)
    lab_test.go:548: preview:
        # reset password (administrative)
        dn: CN=Temp tmp.d655fd,OU=Support,OU=People,OU=Lab,DC=lab,DC=conductor,DC=test
        changetype: modify
        replace: unicodePwd
        unicodePwd: <redacted>
        -
        replace: pwdLastSet
        pwdLastSet: 0
        -
    lab_test.go:556: helpdesk resetting a Domain Admin: ad: modify CN=Lab Admin,OU=Special,OU=Lab,DC=lab,DC=conductor,DC=test: ad: access denied: LDAP Result Code 50 "Insufficient Access Rights": error in module acl: insufficient access rights during LDB_MODIFY (50)
    lab_test.go:573: kpasswd with a wrong old password: ad: kerberos sign-in refused: invalid credentials (KDC_ERR_PREAUTH_FAILED)
    lab_test.go:582: reset (admin/helpdesk) and change (self, LDAP and kpasswd) behave as expected
--- PASS: TestLabPasswordChangeVsReset (1.08s)
    lab_test.go:601: dc1 stopped
    lab_test.go:613: dc1 preferred but down: bound to dc2.lab.conductor.test
--- PASS: TestLabZFailover (2.79s)
PASS
=== sambatool package (on dc1 as root)
    lab_test.go:36: $ samba-tool domain level show
    lab_test.go:41: {Forest:(Windows) 2016 Domain:(Windows) 2016 LowestDC:(Windows) 2016}
--- PASS: TestLabDomainLevel (0.59s)
    lab_test.go:51: $ samba-tool drs showrepl --json
    lab_test.go:57: inbound DC=lab,DC=conductor,DC=test from Default-First-Site-Name\DC2: failures=0 "was successful"
    lab_test.go:57: inbound CN=Configuration,DC=lab,DC=conductor,DC=test from Default-First-Site-Name\DC2: failures=0 "was successful"
    lab_test.go:57: inbound CN=Schema,CN=Configuration,DC=lab,DC=conductor,DC=test from Default-First-Site-Name\DC2: failures=0 "was successful"
    lab_test.go:57: inbound DC=DomainDnsZones,DC=lab,DC=conductor,DC=test from Default-First-Site-Name\DC2: failures=0 "was successful"
    lab_test.go:57: inbound DC=ForestDnsZones,DC=lab,DC=conductor,DC=test from Default-First-Site-Name\DC2: failures=0 "was successful"
--- PASS: TestLabReplication (0.63s)
    lab_test.go:71: zones: [lab.conductor.test _msdcs.lab.conductor.test]
    lab_test.go:77: $ samba-tool dns add --use-kerberos=off -U lab.admin -- dc1.lab.conductor.test lab.conductor.test conductor-test-f1c7db A 10.93.0.250
    lab_test.go:88: query: {Name: Type:A Data:10.93.0.250 TTL:900 Flags:f0}
    lab_test.go:93: after delete: sambatool: dns query exited 255: ERROR(runtime): Record or zone does not exist. [WERR_DNS_ERROR_NAME_DOES_NOT_EXIST] - (9714, 'WERR_DNS_ERROR_NAME_DOES_NOT_EXIST')
--- PASS: TestLabDNSWithPasswordFD (1.21s)
PASS
=== exit: ad=0 sambatool=0
```
