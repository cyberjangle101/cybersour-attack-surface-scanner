package main

// The three roles, from least to most privileged.
//
//	viewer  reads everything (dashboard, findings, assets, reports) and changes nothing
//	analyst viewer + triage: accept risk, reopen, change a finding's severity, start scans, run connection checks
//	admin   analyst + scope and system: add/edit/remove domains, settings, users, sign-in methods, audit log
const (
	RoleViewer  = "viewer"
	RoleAnalyst = "analyst"
	RoleAdmin   = "admin"
)

// Permission levels a route can require.
const (
	permView   = 0 // any signed-in user
	permTriage = 1 // analyst or admin
	permAdmin  = 2 // admin only
)

// roleLevel maps a role name to its permission level (unknown roles get none).
func roleLevel(role string) int {
	switch role {
	case RoleAdmin:
		return permAdmin
	case RoleAnalyst:
		return permTriage
	case RoleViewer:
		return permView
	}
	return -1
}

// validRole reports whether role is one of the three known roles.
func validRole(role string) bool { return roleLevel(role) >= 0 }

// roleLabel is the text shown for a role in the interface.
func roleLabel(role string) string {
	switch role {
	case RoleAdmin:
		return "Administrator"
	case RoleAnalyst:
		return "Analyst"
	}
	return "Viewer"
}
