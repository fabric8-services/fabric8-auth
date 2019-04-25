package service

import (
	"context"
	"fmt"
	"sync"
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
	"github.com/fabric8-services/fabric8-auth/notification"

	"github.com/jinzhu/gorm"
	"github.com/panjf2000/ants"
	errs "github.com/pkg/errors"
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
	GetUserDeactivationInactivityNotificationPeriodDays() time.Duration
	GetUserDeactivationInactivityPeriodDays() time.Duration
	GetPostDeactivationNotificationDelayMillis() time.Duration
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

// NotifyIdentitiesBeforeDeactivation list identities (with a limit) who are soon eligible for account deactivation,
// sends a notification to each one and record the timestamp of the notification as a marker before upcoming deactivation
func (s *userServiceImpl) NotifyIdentitiesBeforeDeactivation(ctx context.Context, now func() time.Time) ([]repository.Identity, error) {
	since := now().Add(-s.config.GetUserDeactivationInactivityNotificationPeriodDays()) // remove 'n' days from now (default: 24)
	limit := s.config.GetUserDeactivationFetchLimit()
	identities, err := s.Repositories().Identities().ListIdentitiesToNotifyForDeactivation(ctx, since, limit)
	if err != nil {
		return nil, errs.Wrap(err, "unable to send notification to users before account deactivation")
	}
	// for each identity, send a notification and record the timestamp in a separate transaction.
	// perform the task for each identity in a separate Tx, and just log the error if something wrong happened,
	// but don't stop processing on the rest of the accounts.
	expirationDate := GetExpiryDate(s.config, now)
	// run the notification/record update in a separate routine, with pooling of child routines to avoid
	// sending too many requests at once to the notification service and to the database
	defer ants.Release()
	var wg sync.WaitGroup
	p, err := ants.NewPoolWithFunc(10, func(id interface{}) {
		defer wg.Done()
		identity, ok := id.(repository.Identity)
		// just to make sure that the arg type is valid.
		if !ok {
			log.Error(ctx, map[string]interface{}{}, "argument is not an identity")
			return
		}
		err := s.notifyIdentityBeforeDeactivation(ctx, identity, expirationDate, now)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"error":    err,
				"username": identity.Username,
			}, "error while notifying user before account deactivation")
		} else {
			log.Info(ctx, map[string]interface{}{
				"username": identity.Username,
			}, "notified user before account deactivation")
		}
		// include a small delay to give time to notification service and database to handle the requests
		time.Sleep(s.config.GetPostDeactivationNotificationDelayMillis())
	})
	if err != nil {
		return nil, errs.Wrap(err, "unable to send notification to users before account deactivation")
	}

	defer func() {
		err := p.Release()
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"error": err,
			}, "error while releasing the go routine pool")
		}
	}()
	for _, identity := range identities {
		wg.Add(1)
		err := p.Invoke(identity)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"error": err,
			}, "error while notifying about account deactivation")
		}
	}
	wg.Wait()
	return identities, nil
}

// GetExpiryDate a utility function which returns the expiry date, ie, when the user deactivation will happen
// The date is based on the given 'now', and takes into account the delay for which the user is given a chance
// to come back (7 days by default)
func GetExpiryDate(config UserServiceConfiguration, now func() time.Time) string {
	return now().
		Add(config.GetUserDeactivationInactivityPeriodDays() - config.GetUserDeactivationInactivityNotificationPeriodDays()).
		Format("Mon Jan 2")
}

// ListIdentitiesToDeactivate lists the identities to deactivate
func (s *userServiceImpl) ListIdentitiesToDeactivate(ctx context.Context, now func() time.Time) ([]repository.Identity, error) {
	since := now().Add(-s.config.GetUserDeactivationInactivityPeriodDays())                                                                        // remove 'n' days from now (default: 31)
	notification := now().Add(s.config.GetUserDeactivationInactivityNotificationPeriodDays() - s.config.GetUserDeactivationInactivityPeriodDays()) // make sure that the notification was sent at least `n` days earlier (default: 7)
	limit := s.config.GetUserDeactivationFetchLimit()

	return s.Repositories().Identities().ListIdentitiesToDeactivate(ctx, since, notification, limit)
}

func (s *userServiceImpl) notifyIdentityBeforeDeactivation(ctx context.Context, identity repository.Identity, expirationDate string, now func() time.Time) error {
	msg := notification.NewUserDeactivationEmail(identity.ID.String(), identity.User.Email, expirationDate)
	_, err := s.Services().NotificationService().SendMessageAsync(ctx, msg)
	if err != nil {
		return errs.Wrap(err, "failed to send notification to user before account deactivation")
	}
	if err := s.ExecuteInTransaction(func() error {
		notificationDate := now()
		identity.DeactivationNotification = &notificationDate
		return s.Repositories().Identities().Save(ctx, &identity)
	}); err != nil {
		return errs.Wrap(err, "failed to record timestamp of notification sent to user before account deactivation")
	}
	return nil
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
	// call Che
	// call WIT and Tenant to deactivate the user there as well,
	// using `auth` SA token here, not the request context's token
	err = s.Services().CheService().DeleteUser(ctx, *identity)
	if err != nil {
		// do not proceed with tenant removal if something wrong happened during Che cleanup
		return nil, errs.Wrapf(err, "error occurred during deactivation of user '%s' on Che Service", identity.ID)
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
