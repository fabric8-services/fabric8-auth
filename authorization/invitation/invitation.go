package invitation

import (
	"github.com/satori/go.uuid"
)

// Invitation is a DTO used to pass state between the controller and service layers when issuing new invitations
type Invitation struct {
	IdentityID *uuid.UUID
	UserEmail  *string
	UserName   *string
	Roles      []string
	Member     bool
}

// InvitationDetail is used to provide a user with details of the invitations they have received.
type InvitationDetail struct {
	// ResourceType is the name of the resource type to which the user has been issued an invitation
	ResourceType string
	// Description is a description of the organization, team, security group or resource to which the user has been issued an invitation
	Description string
	// Member this property indicates whether the user has been invited to join as a member
	Member bool
	// Roles this property indicates the list of roles that the user has been invited to accept
	Roles []string
}
