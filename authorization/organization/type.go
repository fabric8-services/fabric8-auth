package organization

import (
	uuid "github.com/satori/go.uuid"
)

const (
	OrganizationOwnerRole = "owner"
)

// This struct is used to return the Organizations for which an Identity is associated
type IdentityOrganization struct {
	OrganizationID uuid.UUID
	Name           string
	Member         bool
	Roles          []string
}
