package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/errors"
)

// NewUserService creates a new service to manage users
func NewUserService(context servicecontext.ServiceContext) *userServiceImpl {
	return &userServiceImpl{base.NewBaseService(context)}
}

// userServiceImpl implements the UserService to manage users
type userServiceImpl struct {
	base.BaseService
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
