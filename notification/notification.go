package notification

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

type Configuration interface {
	GetNotificationServiceURL() string
}

// Message represents a new event of a Type for a Target performed by a User
// See helper constructors like NewUserEmailUpdated
type Message struct {
	MessageID   uuid.UUID // unique ID per event
	UserID      *string
	Custom      map[string]interface{}
	TargetID    string
	MessageType string
}

func (m Message) String() string {
	return fmt.Sprintf("id:%v type:%v by:%v for:%v", m.MessageID, m.MessageType, m.UserID, m.TargetID)
}

// NewUserEmailUpdated is a helper constructor which returns a Message with contents of the notification
// that would be sent out.
func NewUserEmailUpdated(identityID string, custom map[string]interface{}) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "user.email.update",
		TargetID:    identityID,
		UserID:      &identityID, // in future if service accounts are allowed to update, this will be handy.
		Custom:      custom,
	}
}

// NewTeamInvitationEmail creates a Message for the notification service in order to send an invitation e-mail to a user
//
// The following custom parameter values are required:
//
// teamName - the name of the team
// inviter - the name of the user sending the invitation
// spaceName - the name of the space to which the team belongs
// acceptToken - the unique acceptance token value
func NewTeamInvitationEmail(identityID string, teamName string, inviterName string, spaceName string, acceptURL string) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "invitation.team.noorg",
		TargetID:    identityID,
		UserID:      &identityID,
		Custom: map[string]interface{}{
			"teamName":  teamName,
			"inviter":   inviterName,
			"spaceName": spaceName,
			"acceptURL": acceptURL,
		},
	}
}

// NewSpaceInvitationEmail creates a Message for the notification service in order to send an invitation e-mail to a user
//
// The following custom parameter values are required:
//
// spaceName - the name of the space
// inviter - the name of the user sending the invitation
// roleNames - a comma-separated list of role names
// acceptToken - the unique acceptance token value
func NewSpaceInvitationEmail(identityID string, spaceName string, inviterName string, roleNames string, acceptURL string) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "invitation.space.noorg",
		TargetID:    identityID,
		UserID:      &identityID,
		Custom: map[string]interface{}{
			"spaceName": spaceName,
			"inviter":   inviterName,
			"roleNames": roleNames,
			"acceptURL": acceptURL,
		},
	}
}

// NewUserDeactivationEmail is a helper constructor which returns a message to inform the user that her
// account will be deactivated soon
func NewUserDeactivationEmail(identityID, email, deactivationDate string) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "user.deactivation",
		TargetID:    identityID,
		UserID:      &identityID,
		Custom: map[string]interface{}{
			"userEmail":  email,
			"expiryDate": deactivationDate,
		},
	}
}
