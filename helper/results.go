package helper

import "time"

// Result types of the read-only operations, shared by the helper (which
// encodes them) and its callers (which decode them with DecodeResult).

// PingResult answers OpPing.
type PingResult struct {
	Version int       `json:"version"`
	Time    time.Time `json:"time"`
}

// DomainLevelResult answers OpDomainLevel (functional levels).
type DomainLevelResult struct {
	Forest   string `json:"forest"`
	Domain   string `json:"domain"`
	LowestDC string `json:"lowest_dc"`
}

// FSMORole is one operations-master role and its owner (NTDS Settings DN).
type FSMORole struct {
	Role  string `json:"role"`
	Owner string `json:"owner"`
}

// FSMORolesResult answers OpFSMORoles.
type FSMORolesResult struct {
	Roles []FSMORole `json:"roles"`
}

// DCListResult answers OpDCList: the DNs of the domain controllers' computer
// accounts (members of "Domain Controllers").
type DCListResult struct {
	DCs []string `json:"dcs"`
}
