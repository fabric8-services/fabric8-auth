package service

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/application/service"

	"github.com/fabric8-services/fabric8-auth/account/repository"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/satori/go.uuid"
)

// NewUserService creates a new service to manage users
func NewUserService(ctx servicecontext.ServiceContext) service.UserService {
	return &userServiceImpl{
		BaseService: base.NewBaseService(ctx),
	}
}

// userServiceImpl implements the UserService to manage users
type userServiceImpl struct {
	base.BaseService
	tokenManager token.Manager
}

// UserInfo gets user information given a context containing access_token
func (s *userServiceImpl) UserInfo(ctx context.Context, identityID uuid.UUID) (*account.User, *account.Identity, error) {
	var identity *account.Identity
	err := s.ExecuteInTransaction(func() error {
		var err error
		identity, err = s.Repositories().Identities().LoadWithUser(ctx, identityID)
		if err != nil || identity == nil {
			return errors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", identityID))
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	log.Debug(ctx, map[string]interface{}{
		"identity_id": identity.ID,
		"user_id":     identity.User.ID,
	}, "loaded identity and user")
	return &identity.User, identity, nil
}

func (s *userServiceImpl) DeprovisionUser(ctx context.Context, username string) (*repository.Identity, error) {

	var identity *repository.Identity
	err := s.ExecuteInTransaction(func() error {

		identities, err := s.Repositories().Identities().Query(
			repository.IdentityWithUser(),
			repository.IdentityFilterByUsername(username),
			repository.IdentityFilterByProviderType(repository.KeycloakIDP))
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			return errors.NewNotFoundErrorWithKey("user identity", "username", username)
		}

		identity = &identities[0]
		identity.User.Deprovisioned = true

		return s.Repositories().Users().Save(ctx, &identity.User)
	})

	return identity, err
}
