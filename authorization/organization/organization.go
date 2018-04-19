package organization

import (
	"github.com/satori/go.uuid"
)

// IdentityOrganization is used to return the Organizations for which an Identity is associated
type IdentityOrganization struct {
	OrganizationID uuid.UUID
	Name           string
	Member         bool
	Roles          []string
}
