package organization

import (
	uuid "github.com/satori/go.uuid"
)

const (
	// OrganizationOwnerRole is the constant used to denotee the name of the owner's role
	OrganizationOwnerRole = "owner"
)

// IdentityOrganization is used to return the Organizations for which an Identity is associated
type IdentityOrganization struct {
	OrganizationID uuid.UUID
	Name           string
	Member         bool
	Roles          []string
}
