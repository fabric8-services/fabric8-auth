package base

import (
	"github.com/fabric8-services/fabric8-auth/application/service/context"
)

// BaseService provides transaction control and other common features for service implementations
type BaseService struct {
	context.ServiceContext
}

func NewBaseService(context *context.ServiceContext) BaseService {
	return BaseService{*context}
}
