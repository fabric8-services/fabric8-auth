package userinfo

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
)

func NewUserInfoProvider(identities account.IdentityRepository, users account.UserRepository, tokenManager token.Manager, db application.DB) *UserInfoProvider {
	return &UserInfoProvider{
		Identities:   identities,
		Users:        users,
		TokenManager: tokenManager,
		DB:           db,
	}
}

type UserInfoProvider struct {
	Identities      account.IdentityRepository
	Users           account.UserRepository
	TokenManager    token.Manager
	DB              application.DB
	UserInfoService UserInfoService
}

type UserInfoService interface {
	UserInfo(ctx context.Context) (*account.User, *account.Identity, error)
}

// UserInfo gets user infomation given a context containing access_token
func (userInfoProvider *UserInfoProvider) UserInfo(ctx context.Context) (*account.User, *account.Identity, error) {

	id, err := userInfoProvider.TokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return nil, nil, autherrors.NewUnauthorizedError("bad token")
	}
	var user *account.User
	var identity *account.Identity
	err = application.Transactional(userInfoProvider.DB, func(appl application.Application) error {

		identity, err = appl.Identities().Load(ctx, id)
		if err != nil || identity == nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": id,
				"err":         err,
			}, "Auth token contains id %s of unknown Identity", id)
			return autherrors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", id))
		}

		userID := identity.UserID
		if userID.Valid {
			user, err = appl.Users().Load(ctx, userID.UUID)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"user_id": userID,
					"err":     err,
				}, "Can't load user with id %s", userID)
				return autherrors.NewUnauthorizedError(fmt.Sprintf("can't load user with id %s", userID.UUID))
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return user, identity, nil
}
