package service

import (
	"context"
	"fmt"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa/uuid"
)

// devNullNotificationService is the default dev service implementation. It does nothing.
type devNullNotificationService struct{}

func (s *devNullNotificationService) SendAsync(ctx context.Context, msg notification.Message) error {
	return nil
}

func (s *devNullNotificationService) SendMessagesAsync(ctx context.Context, messages []notification.Message) error {
	return nil
}

type notificationServiceImpl struct {
	base.BaseService
	config notification.Configuration
	doer   rest.HttpDoer
}

// NewNotificationService creates a new service.
func NewNotificationService(context servicecontext.ServiceContext, config notification.Configuration) service.NotificationService {
	if config.GetNotificationServiceURL() == "" {
		return &devNullNotificationService{}
	}
	return &notificationServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
		doer:        rest.DefaultHttpDoer(),
	}
}

// SendAsync creates a new goroutine and sends a message to fabric8-notification service
func (s *notificationServiceImpl) SendAsync(ctx context.Context, msg notification.Message) error {
	c, err := s.createClientWithContextSigner(ctx)
	if err != nil {
		return err
	}

	go s.send(ctx, c, msg)

	return nil
}

// SendMessagesAsync creates a new goroutine and sends multiple messages to fabric8-notification service
func (s *notificationServiceImpl) SendMessagesAsync(ctx context.Context, messages []notification.Message) error {
	c, err := s.createClientWithContextSigner(ctx)
	if err != nil {
		return err
	}

	go func() {
		for _, msg := range messages {
			s.send(ctx, c, msg)
		}
	}()

	return nil
}

func (s *notificationServiceImpl) send(ctx context.Context, c *client.Client, msg notification.Message) error {
	msgID := uuid.UUID(msg.MessageID)

	resp, err := c.SendNotify(
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
		return err
	}

	defer rest.CloseResponse(resp)
	if resp.StatusCode >= 400 {
		body := rest.ReadBody(resp.Body)
		err := errors.NewInternalErrorFromString(ctx, fmt.Sprintf("unexpected response code: %s; response body: %s", resp.Status, body))
		log.Error(ctx, map[string]interface{}{
			"status":     resp.StatusCode,
			"message_id": msg.MessageID,
			"type":       msg.MessageType,
			"target_id":  msg.TargetID,
			"custom":     msg.Custom,
			"err":        err,
		}, "unexpected response code")
		return err
	}

	return nil
}

// createClientWithContextSigner creates with a signer based on current context
func (t *notificationServiceImpl) createClientWithContextSigner(ctx context.Context) (*client.Client, error) {
	c, err := t.createClient()
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}

func (t *notificationServiceImpl) createClient() (*client.Client, error) {
	u, err := url.Parse(t.config.GetNotificationServiceURL())
	if err != nil {
		return nil, err
	}

	c := client.New(t.doer)
	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
