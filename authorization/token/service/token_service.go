package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/satori/go.uuid"
)

type tokenServiceImpl struct {
	base.BaseService
}

func NewTokenService(context servicecontext.ServiceContext) service.TokenService {
	return &tokenServiceImpl{
		BaseService: base.NewBaseService(context),
	}
}

func (s *tokenServiceImpl) Initialize(ctx context.Context, resourceID string) (token.RPTTokenState, error) {
	var token token.RPTTokenState

	return token, nil
}

func (s *tokenServiceImpl) ValidateToken(ctx context.Context, tokenID uuid.UUID) (bool, error) {
	return false, nil
}

func (s *tokenServiceImpl) Refresh(ctx context.Context, tokenID uuid.UUID, resourceID string) (token.RPTTokenState, error) {
	var token token.RPTTokenState

	return token, nil
}
