package invitation

import (
	"github.com/satori/go.uuid"
)

type Invitation struct {
	IdentityID *uuid.UUID
	UserEmail  *string
	UserName   *string
	Roles      []string
	Member     bool
}

/* This struct is used to provide a user with details of the invitations they have received.
 * The ResourceType property indicates
 */
type InvitationDetail struct {
	ResourceType string
	Description  string
	Member       bool
	Roles        []string
}
