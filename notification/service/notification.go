package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/notification/client"
	"github.com/fabric8-services/fabric8-auth/rest"

	goaclient "github.com/goadesign/goa/client"
	"github.com/goadesign/goa/uuid"
)

type notificationServiceImpl struct {
	base.BaseService
	config notification.Configuration
}

// NewNotificationService creates a new service.
func NewNotificationService(context servicecontext.ServiceContext, config notification.Configuration) service.NotificationService {
	return &notificationServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// SendMessageAsync creates a new goroutine and sends a message to fabric8-notification service
// chan error is used to send any errors received from remote notification service.
// we might get an error while creating client which is before actual remote call to notification service, so using return type (chan error, error)
func (s *notificationServiceImpl) SendMessageAsync(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) (chan error, error) {
	c, err := s.createClientWithContextSigner(ctx, options...)
	if err != nil {
		return nil, err
	}

	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		if e := s.send(ctx, c, msg); e != nil {
			errs <- e
		}
	}()

	return errs, nil
}

// SendMessagesAsync creates a new goroutine and sends multiple messages to fabric8-notification service
// chan error is used to send any errors received from remote notification service.
// we might get an error while creating client which is before actual remote call to notification service, so using return type (chan error, error)
func (s *notificationServiceImpl) SendMessagesAsync(ctx context.Context, messages []notification.Message, options ...rest.HTTPClientOption) (chan error, error) {
	c, err := s.createClientWithContextSigner(ctx, options...)
	if err != nil {
		return nil, err
	}
	errs := make(chan error, len(messages))
	go func() {
		defer close(errs)
		for _, msg := range messages {
			if e := s.send(ctx, c, msg); e != nil {
				errs <- e
			}
			s.send(ctx, c, msg)
		}
	}()

	return errs, nil
}

func (s *notificationServiceImpl) send(ctx context.Context, c *client.Client, msg notification.Message) error {
	msgID := uuid.UUID(msg.MessageID)
	resp, err := c.SendNotify(
		goasupport.ForwardContextRequestID(ctx),
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
func (s *notificationServiceImpl) createClientWithContextSigner(ctx context.Context, options ...rest.HTTPClientOption) (*client.Client, error) {
	c, err := s.createClient(options...)
	if err != nil {
		return nil, err
	}
	sgn := token.NewSATokenSigner(ctx)
	saTokenSigner, err := sgn.Signer()
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(saTokenSigner)
	return c, nil
}

func (s *notificationServiceImpl) createClient(options ...rest.HTTPClientOption) (*client.Client, error) {
	u, err := url.Parse(s.config.GetNotificationServiceURL())
	if err != nil {
		return nil, err
	}

	httpClient := http.DefaultClient

	// apply options
	for _, opt := range options {
		opt(httpClient)
	}
	c := client.New(goaclient.HTTPClientDoer(httpClient))

	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
