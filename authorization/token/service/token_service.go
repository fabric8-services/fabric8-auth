package service

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
)

type tokenServiceImpl struct {
	base.BaseService
}

func NewTokenService(context servicecontext.ServiceContext) service.TokenService {
	return &tokenServiceImpl{
		BaseService: base.NewBaseService(context),
	}
}
