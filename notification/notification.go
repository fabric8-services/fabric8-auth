package notification

import (
	"fmt"

	"github.com/satori/go.uuid"
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
func NewUserEmailUpdated(userID string, custom map[string]interface{}) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "user.email.update",
		TargetID:    userID,
		UserID:      &userID, // in future if service accounts are allowed to update, this will be handy.
		Custom:      custom,
	}
}
