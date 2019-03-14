package service

import (
	"context"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// NewUserService creates a new service to manage users
func NewUserService(ctx servicecontext.ServiceContext, config UserServiceConfiguration) service.UserService {
	return &userServiceImpl{
		BaseService: base.NewBaseService(ctx),
		config:      config,
	}
}

// UserServiceConfiguration the configuration for the User service
type UserServiceConfiguration interface {
	GetUserDeactivationFetchLimit() int
	GetUserDeactivationInactivityNotificationPeriod() int
	GetUserDeactivationInactivityPeriod() int
}

// userServiceImpl implements the UserService to manage users
type userServiceImpl struct {
	base.BaseService
	config UserServiceConfiguration
}

// ResetBanned sets User.Banned to false
func (s *userServiceImpl) ResetBan(ctx context.Context, user repository.User) error {
	user.Banned = false
	return s.ExecuteInTransaction(func() error {
		return s.Repositories().Users().Save(ctx, &user)
	})
}

// IdentityByUsernameAndEmail returns a an identity by the given username which belongs to the user with the given email
// Returns nil if no identity/user with such username/email found
func (s *userServiceImpl) IdentityByUsernameAndEmail(ctx context.Context, username, email string) (*repository.Identity, error) {
	identities, err := s.Repositories().Identities().Query(repository.IdentityFilterByUsername(username), repository.IdentityFilterByProviderType(repository.DefaultIDP), repository.IdentityWithUser())
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if identity.UserID.Valid && identity.User.Email == email {
			return &identity, nil
		}
	}
	return nil, nil
}

// UserInfo gets user information given a context containing access_token
func (s *userServiceImpl) UserInfo(ctx context.Context, identityID uuid.UUID) (*repository.User, *repository.Identity, error) {
	var identity *repository.Identity
	err := s.ExecuteInTransaction(func() error {
		var err error
		identity, err = s.Repositories().Identities().LoadWithUser(ctx, identityID)
		if err != nil {
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

func (s *userServiceImpl) BanUser(ctx context.Context, username string) (*repository.Identity, error) {

	var identity *repository.Identity
	err := s.ExecuteInTransaction(func() error {

		identities, err := s.Repositories().Identities().Query(
			repository.IdentityWithUser(),
			repository.IdentityFilterByUsername(username),
			repository.IdentityFilterByProviderType(repository.DefaultIDP))
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			return errors.NewNotFoundErrorWithKey("user identity", "username", username)
		}

		identity = &identities[0]
		identity.User.Banned = true
		identity.User.Deprovisioned = true // for backward compatibility

		return s.Repositories().Users().Save(ctx, &identity.User)
	})

	return identity, err
}

func (s *userServiceImpl) ListIdentitiesToNotifyBeforeDeactivation(ctx context.Context) ([]repository.Identity, error) {
	since := time.Now().Add(time.Duration(-s.config.GetUserDeactivationInactivityNotificationPeriod() * 24) * time.Hour) // remove 'n' days from now
	limit := s.config.GetUserDeactivationFetchLimit()
	return s.Repositories().Identities().ListIdentitiesToDeactivate(ctx, since, limit)
}

func (s *userServiceImpl) ListIdentitiesToDeactivate(ctx context.Context) ([]repository.Identity, error) {
	since := time.Now().Add(time.Duration(-s.config.GetUserDeactivationInactivityPeriod()*-1*24) * time.Hour) // remove 'n' days from now
	limit := s.config.GetUserDeactivationFetchLimit()
	return s.Repositories().Identities().ListIdentitiesToDeactivate(ctx, since, limit)
}

// DeactivateUser deactivates a user, i.e., mark her as `active=false`, obfuscate the personal info and soft-delete the account
func (s *userServiceImpl) DeactivateUser(ctx context.Context, username string) (*repository.Identity, error) {
	var identity *repository.Identity
	if err := s.ExecuteInTransaction(func() error {
		identities, err := s.Repositories().Identities().Query(
			repository.IdentityWithUser(),
			repository.IdentityFilterByUsername(username),
			repository.IdentityFilterByProviderType(repository.DefaultIDP))
		if err != nil {
			return err
		}
		if len(identities) == 0 {
			return errors.NewNotFoundErrorWithKey("user identity", "username", username)
		}
		identity = &identities[0]
		// unlink external accounts (while we still have the user.Cluster info)
		err = s.Services().TokenService().DeleteExternalToken(ctx, identity.ID, "", provider.GitHubProviderAlias)
		if err != nil {
			return err
		}
		err = s.Services().TokenService().DeleteExternalToken(ctx, identity.ID, "", provider.OpenShiftProviderAlias)
		if err != nil {
			return err
		}

		// mark the account as inactive
		identity.User.Active = false
		// obfuscate the data
		obfuscatated := uuid.NewV4().String()
		identity.Username = obfuscatated
		identity.ProfileURL = &obfuscatated
		identity.User.Email = obfuscatated
		identity.User.FullName = obfuscatated
		identity.User.ImageURL = obfuscatated
		identity.User.URL = obfuscatated
		identity.User.Company = obfuscatated
		identity.User.Bio = obfuscatated
		identity.User.Cluster = obfuscatated
		identity.User.FeatureLevel = obfuscatated
		// empty data
		identity.User.ContextInformation = account.ContextInformation{}
		err = s.Repositories().Identities().Save(ctx, identity)
		if err != nil {
			return err
		}
		err = s.Repositories().Users().Save(ctx, &identity.User)
		if err != nil {
			return err
		}
		// revoke all user's tokens
		err = s.Services().TokenService().SetStatusForAllIdentityTokens(ctx, identity.ID, token.TOKEN_STATUS_REVOKED)
		if err != nil {
			return err
		}
		// soft-delete user account
		if err := s.Repositories().Identities().Delete(ctx, identity.ID); err != nil {
			return err
		}
		return s.Repositories().Users().Delete(ctx, identity.User.ID)
	}); err != nil {
		return nil, err
	}

	// call WIT and Tenant to deactivate the user there as well,
	// using `auth` SA token here, not the request context's token
	err := s.Services().WITService().DeleteUser(ctx, identity.ID.String())
	if err != nil {
		// just log the error but don't suspend the deactivation
		log.Error(ctx, map[string]interface{}{"identity_id": identity.ID, "error": err}, "error occurred during user deactivation on WIT Service")
	}
	err = s.Services().TenantService().Delete(ctx, identity.ID)
	if err != nil {
		return nil, err
	}
	return identity, err
}

// ContextIdentityIfExists returns the identity's ID found in given context if the identity exists in the Auth DB
// If it doesn't exist then an Unauthorized error is returned
func (s *userServiceImpl) ContextIdentityIfExists(ctx context.Context) (uuid.UUID, error) {
	identity, err := manager.ContextIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	// Check if the identity exists
	err = s.ExecuteInTransaction(func() error {
		err := s.Repositories().Identities().CheckExists(ctx, identity.String())
		if err != nil {
			return errors.NewUnauthorizedError(err.Error())
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return *identity, nil
}

// LoadContextIdentityAndUser returns the identity found in given context if the identity exists in the Auth DB
// If no token present in the context then an Unauthorized error is returned
// If the identity represented by the token doesn't exist in the DB or not associated with any User then an Unauthorized error is returned
func (s *userServiceImpl) LoadContextIdentityAndUser(ctx context.Context) (*repository.Identity, error) {
	identityID, err := manager.ContextIdentity(ctx)
	if err != nil {
		return nil, errors.NewUnauthorizedError(err.Error())
	}
	// Check if the identity exists
	identity, err := s.Repositories().Identities().LoadWithUser(ctx, *identityID)
	if err != nil {
		return nil, errors.NewUnauthorizedError(err.Error())
	}

	return identity, err
}

// LoadContextIdentityIfNotBanned returns the same identity as LoadContextIdentityAndUser()
// if the user is not banned. Returns an Unauthorized error if the user is banned.
func (s *userServiceImpl) LoadContextIdentityIfNotBanned(ctx context.Context) (*repository.Identity, error) {
	identity, err := s.LoadContextIdentityAndUser(ctx)
	if err != nil {
		return nil, err
	}
	if identity.User.Banned {
		return nil, errors.NewUnauthorizedError("user banned")
	}
	return identity, err
}

func (s *userServiceImpl) HardDeleteUser(ctx context.Context, identity repository.Identity) error {
	return s.ExecuteInTransaction(func() error {
		unscoped := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}
		if err := s.Repositories().Identities().Delete(ctx, identity.ID, unscoped); err != nil {
			return err
		}

		if err := s.Repositories().Users().Delete(ctx, identity.User.ID, unscoped); err != nil {
			return err
		}
		return nil
	})
}
