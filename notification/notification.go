package notification

import (
	"context"
	"net/http"
	"net/url"

	"fmt"

	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	goaclient "github.com/goadesign/goa/client"
	goauuid "github.com/goadesign/goa/uuid"
	uuid "github.com/satori/go.uuid"
)

// Channel is a simple interface between the notifying component and the notificaiton impl
type Channel interface {
	Send(context.Context, Message)
}

// Message represents a new event of a Type for a Target performed by a User
// See helper constructors like NewWorkItemCreated, NewCommentUpdated
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

func NewUserEmailUpdated(userID string, custom map[string]interface{}) Message {
	return Message{
		MessageID:   uuid.NewV4(),
		MessageType: "user.email.update",
		TargetID:    userID,
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
	config ServiceConfiguration
}

func validateConfig(config ServiceConfiguration) error {
	_, err := url.Parse(config.GetNotificationServiceURL())
	if err != nil {
		return fmt.Errorf("Invalid NotificationServiceURL %v cause %v", config.GetNotificationServiceURL(), err.Error())
	}
	return nil
}

// NewServiceChannel sends notification messages to the fabric8-notification service
func NewServiceChannel(config ServiceConfiguration) (Channel, error) {
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	return &Service{config: config}, nil
}

// Send invokes the fabric8-notification API
func (s *Service) Send(ctx context.Context, msg Message) {
	go func(ctx context.Context, msg Message) {

		u, err := url.Parse(s.config.GetNotificationServiceURL())
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"url": s.config.GetNotificationServiceURL(),
				"err": err,
			}, "unable to parse GetNotificationServiceURL")
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
				"err":        err,
			}, "unexpected response code")
		}
		defer resp.Body.Close()

	}(ctx, msg)
}
