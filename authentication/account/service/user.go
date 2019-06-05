package service

import (
	"context"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/metric"

	"github.com/fabric8-services/admin-console/auditlog"
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
	GetUserDeactivationInactivityNotificationPeriod() time.Duration
	GetUserDeactivationInactivityPeriod() time.Duration
	GetUserDeactivationRescheduleDelay() time.Duration
	GetUserDeactivationWhiteList() []string
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

		err = s.Repositories().Users().Save(ctx, &identity.User)
		if err != nil {
			return err
		}

		// revoke all user's tokens
		return s.Services().TokenService().SetStatusForAllIdentityTokens(ctx, identity.ID, token.TOKEN_STATUS_REVOKED)
	})

	if err == nil {
		err = s.deleteUserFromOtherServices(ctx, identity)
	}

	return identity, err
}

// NotifyIdentitiesBeforeDeactivation list identities (with a limit) who are soon eligible for account deactivation,
// sends a notification to each one and record the timestamp of the notification as a marker before upcoming deactivation
func (s *userServiceImpl) NotifyIdentitiesBeforeDeactivation(ctx context.Context, now func() time.Time) ([]repository.Identity, error) {
	since := now().Add(-s.config.GetUserDeactivationInactivityNotificationPeriod()) // remove 'n' days from now (default: 24)
	limit := s.config.GetUserDeactivationFetchLimit()
	identities, err := s.Repositories().Identities().ListIdentitiesToNotifyForDeactivation(ctx, since, limit)
	if err != nil {
		return nil, errs.Wrap(err, "unable to send notification to users before account deactivation")
	}

	expirationDate := GetExpiryDate(s.config, now)

	// for each identity, send a notification and record the timestamp in a separate transaction.
	// perform the task for each identity in a separate Tx, and just log the error if something wrong happened,
	// but don't stop processing on the rest of the accounts.
	for _, identity := range identities {
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
		metric.RecordUserDeactivationNotification(err == nil) // record the notification
		// create an audit log to keep track of the user deactivation notification
		err = s.Services().AdminConsoleService().CreateAuditLog(ctx, identity.Username, auditlog.UserDeactivationNotificationEvent)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"error":    err,
				"username": identity.Username,
			}, "error while creating audit log for user deactivation notification")
		}
	}

	return identities, nil
}

// GetExpiryDate a utility function which returns the expiry date, ie, when the user deactivation will happen
// The date is based on the given 'now', and takes into account the delay for which the user is given a chance
// to come back (7 days by default)
func GetExpiryDate(config UserServiceConfiguration, now func() time.Time) string {
	return now().
		Add(config.GetUserDeactivationInactivityPeriod() - config.GetUserDeactivationInactivityNotificationPeriod()).
		Format("Mon Jan 2")
}

// ListIdentitiesToDeactivate lists the identities to deactivate
func (s *userServiceImpl) ListIdentitiesToDeactivate(ctx context.Context, now func() time.Time) ([]repository.Identity, error) {
	since := now().Add(-s.config.GetUserDeactivationInactivityPeriod())                                                                    // remove 'n' days from now (default: 31)
	notification := now().Add(s.config.GetUserDeactivationInactivityNotificationPeriod() - s.config.GetUserDeactivationInactivityPeriod()) // make sure that the notification was sent at least `n` days earlier (default: 7)
	limit := s.config.GetUserDeactivationFetchLimit()

	return s.Repositories().Identities().ListIdentitiesToDeactivate(ctx, since, notification, s.config.GetUserDeactivationWhiteList(), limit)
}

func (s *userServiceImpl) notifyIdentityBeforeDeactivation(ctx context.Context, identity repository.Identity, expirationDate string, now func() time.Time) error {
	msg := notification.NewUserDeactivationEmail(identity.ID.String(), identity.User.Email, expirationDate)
	err := s.Services().NotificationService().SendMessage(ctx, msg)
	if err != nil {
		return errs.Wrap(err, "failed to send notification to user before account deactivation")
	}
	if err := s.ExecuteInTransaction(func() error {
		notificationDate := now()
		identity.DeactivationNotification = &notificationDate
		scheduledDeactivation := notificationDate.Add(s.config.GetUserDeactivationInactivityPeriod()).Add(-s.config.GetUserDeactivationInactivityNotificationPeriod())
		identity.DeactivationScheduled = &scheduledDeactivation
		return s.Repositories().Identities().Save(ctx, &identity)
	}); err != nil {
		return errs.Wrap(err, "failed to record timestamp of notification sent to user before account deactivation")
	}
	return nil
}

// DeactivateUser deactivates a user, i.e., mark her as `active=false`, obfuscate the personal info and soft-delete the account
func (s *userServiceImpl) DeactivateUser(ctx context.Context, username string) (*repository.Identity, error) {
	result, err := s.deactivateUser(ctx, username)
	metric.RecordUserDeactivation(err == nil)
	return result, err
}

func (s *userServiceImpl) deactivateUser(ctx context.Context, username string) (*repository.Identity, error) {
	identities, err := s.Repositories().Identities().Query(
		repository.IdentityWithUser(),
		repository.IdentityFilterByUsername(username),
		repository.IdentityFilterByProviderType(repository.DefaultIDP))
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, errors.NewNotFoundErrorWithKey("user identity", "username", username)
	}
	identity := &identities[0]

	err = s.deleteUserFromOtherServices(ctx, identity)
	if err != nil {
		return nil, err
	}

	// Now it's safe to clean up Auth DB
	if err := s.ExecuteInTransaction(func() error {
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
	// create an audit log to keep track of the user deactivation
	err = s.Services().AdminConsoleService().CreateAuditLog(ctx, username, auditlog.UserDeactivationEvent)
	// just log the error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"error":    err,
			"username": username,
		}, "error while creating audit log for user deactivation")
	}
	// do not return the error logged above.
	return identity, nil
}

// deleteUserFromOtherServices deletes the user from Che and Tenant service
func (s *userServiceImpl) deleteUserFromOtherServices(ctx context.Context, identity *repository.Identity) error {
	// call Che
	err := s.Services().CheService().DeleteUser(ctx, *identity)
	if err != nil {
		// do not proceed with tenant removal if something wrong happened during Che cleanup
		return errs.Wrapf(err, "error occurred during deleting the user '%s' on Che Service", identity.ID)
	}

	// call Tenant to delete the user there as well,
	err = s.Services().TenantService().Delete(ctx, identity.ID)
	if err != nil {
		return errs.Wrapf(err, "error occurred during deleting the user '%s' on Tenant Service", identity.ID)
	}

	return nil
}

// RescheduleDeactivation sets the deactivation schedule to a configurable point of time in the future
func (s *userServiceImpl) RescheduleDeactivation(ctx context.Context, identityID uuid.UUID) error {
	rescheduledDeactivation := time.Now().Add(s.config.GetUserDeactivationRescheduleDelay())

	err := s.ExecuteInTransaction(func() error {
		return s.Repositories().Identities().BumpDeactivationSchedule(ctx, identityID, rescheduledDeactivation)
	})

	return err
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
