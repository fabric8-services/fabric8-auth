package notification

import (
	"context"
	"net/http"
	"net/url"

	"fmt"

	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	"github.com/fabric8-services/fabric8-auth/rest"
	goaclient "github.com/goadesign/goa/client"
	goauuid "github.com/goadesign/goa/uuid"
	uuid "github.com/satori/go.uuid"
)

// Channel is a simple interface between the notifying component and the notificaiton impl
type Channel interface {
	Send(context.Context, Message)
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
		MessageID:   uuid.Must(uuid.NewV4()),
		MessageType: "user.email.update",
		TargetID:    userID,
		UserID:      &userID, // in future if service accounts are allowed to update, this will be handy.
		Custom:      custom,
	}
}

// DevNullChannel is the default configured channel. It does nothing.
type DevNullChannel struct{}

// Send NO-OP
func (d *DevNullChannel) Send(context.Context, Message) {}

// ServiceConfiguration holds configuration options required to interact with the fabric8-notification API
type ServiceConfiguration interface {
	GetNotificationServiceURL() string
}

// Service is a simple client Channel to the fabric8-notification service
type Service struct {
	notificationURL *url.URL
}

func validateConfig(config ServiceConfiguration) (*url.URL, error) {
	notificationURL, err := url.Parse(config.GetNotificationServiceURL())
	if err != nil {
		return nil, fmt.Errorf("Invalid NotificationServiceURL %v cause %v", config.GetNotificationServiceURL(), err.Error())
	}
	return notificationURL, nil
}

// NewServiceChannel sends notification messages to the fabric8-notification service
func NewServiceChannel(config ServiceConfiguration) (Channel, error) {
	notificationURL, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	return &Service{notificationURL: notificationURL}, nil
}

// Send invokes the fabric8-notification API
func (s *Service) Send(ctx context.Context, msg Message) {
	go func(ctx context.Context, msg Message) {

		u := s.notificationURL
		if u == nil {
			log.Error(ctx, map[string]interface{}{
				"custom":     msg.Custom,
				"message_id": msg.MessageID,
				"type":       msg.MessageType,
				"target_id":  msg.TargetID,
			}, "notification url could not be consumed")
			return
		}

		cl := client.New(goaclient.HTTPClientDoer(http.DefaultClient))
		cl.Host = u.Host
		cl.Scheme = u.Scheme
		cl.SetJWTSigner(goasupport.NewForwardSigner(ctx))

		msgID := goauuid.UUID(msg.MessageID)

		resp, err := cl.SendNotify(
			ctx,
			client.SendNotifyPath(),
			&client.SendNotifyPayload{
				Data: &client.Notification{
					Type: "notifications",
					ID:   &msgID,
					Attributes: &client.NotificationAttributes{
						Type:   msg.MessageType,
						ID:     msg.TargetID,
						Custom: msg.Custom,
					},
				},
			},
		)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"custom":     msg.Custom,
				"message_id": msg.MessageID,
				"type":       msg.MessageType,
				"target_id":  msg.TargetID,
				"err":        err,
			}, "unable to send notification")
		} else if resp.StatusCode >= 400 {
			log.Error(ctx, map[string]interface{}{
				"status":     resp.StatusCode,
				"message_id": msg.MessageID,
				"type":       msg.MessageType,
				"target_id":  msg.TargetID,
				"custom":     msg.Custom,
			}, "unexpected response code")
		}
		defer rest.CloseResponse(resp)

	}(ctx, msg)
}
