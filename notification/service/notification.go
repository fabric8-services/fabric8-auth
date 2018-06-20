package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
)

type serviceConfiguration interface {
	GetNotificationServiceURL() string
}

type notificationServiceImpl struct {
	base.BaseService
	config serviceConfiguration
}

// NewNotificationService creates a new service.
func NewNotificationService(context *servicecontext.ServiceContext, config serviceConfiguration) service.NotificationService {
	return &notificationServiceImpl{base.NewBaseService(context), config}
}

func (s *notificationServiceImpl) Send(ctx context.Context) error {
	return nil
}
