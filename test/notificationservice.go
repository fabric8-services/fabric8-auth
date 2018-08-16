package test

import (
	"github.com/fabric8-services/fabric8-auth/notification"
	"context"
	"github.com/fabric8-services/fabric8-auth/test/configuration"
)

// DevNotificationService is the default dev service implementation for Notification used in testing.
type DevNotificationService struct {
	Messages []notification.Message
}

func (n *DevNotificationService) SendAsync(ctx context.Context, msg notification.Message, options ...configuration.HTTPClientOption) (<-chan struct{}, <-chan error, error) {
	n.Messages = append(n.Messages, msg)
	return nil, nil, nil
}

func (n *DevNotificationService) SendMessagesAsync(ctx context.Context, messages []notification.Message, options ...configuration.HTTPClientOption) (<-chan struct{}, <-chan error, error) {
	n.Messages = append(n.Messages, messages...)
	return nil, nil, nil
}
