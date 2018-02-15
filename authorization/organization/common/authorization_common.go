package common

import (
	uuid "github.com/satori/go.uuid"
)

const (
	IdentityResourceTypeOrganization = "identity/organization"
	IdentityResourceTypeTeam         = "identity/team"
	IdentityResourceTypeGroup        = "identity/group"
	IdentityResourceTypeUser         = "identity/user"

	OrganizationOwnerRole = "owner"
)

// This struct is used to return the Organizations for which an Identity is associated
type IdentityOrganization struct {
	OrganizationID uuid.UUID
	Name           string
	Member         bool
	Roles          []string
}
