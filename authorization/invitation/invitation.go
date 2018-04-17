package invitation

import (
	"github.com/satori/go.uuid"
)

// Invitation is a DTO used to pass state between the controller and service layers when issuing new invitations
type Invitation struct {
	IdentityID *uuid.UUID
	Roles      []string
	Member     bool
}
