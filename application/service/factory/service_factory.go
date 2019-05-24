package factory

import (
	"time"

	adminconsoleService "github.com/fabric8-services/fabric8-auth/adminconsole/service"
	factorymanager "github.com/fabric8-services/fabric8-auth/application/factory/manager"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	userservice "github.com/fabric8-services/fabric8-auth/authentication/account/service"
	logoutservice "github.com/fabric8-services/fabric8-auth/authentication/logout/service"
	providerservice "github.com/fabric8-services/fabric8-auth/authentication/provider/service"
	subscriptionservice "github.com/fabric8-services/fabric8-auth/authentication/subscription/service"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	resourceservice "github.com/fabric8-services/fabric8-auth/authorization/resource/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	spaceservice "github.com/fabric8-services/fabric8-auth/authorization/space/service"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
	tokenservice "github.com/fabric8-services/fabric8-auth/authorization/token/service"
	cheservice "github.com/fabric8-services/fabric8-auth/che/service"
	clusterservice "github.com/fabric8-services/fabric8-auth/cluster/service"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	notificationservice "github.com/fabric8-services/fabric8-auth/notification/service"

	"github.com/pkg/errors"
)

type serviceContextImpl struct {
	repositories              repository.Repositories
	transactionalRepositories repository.Repositories
	transactionManager        transaction.TransactionManager
	inTransaction             bool
	services                  service.Services
	factories                 service.Factories
}

func NewServiceContext(repos repository.Repositories, tm transaction.TransactionManager, config *configuration.ConfigurationData,
	wrappers factorymanager.FactoryWrappers, options ...Option) servicecontext.ServiceContext {
	ctx := &serviceContextImpl{}
	ctx.repositories = repos
	ctx.transactionManager = tm
	ctx.inTransaction = false

	var sc servicecontext.ServiceContext
	sc = ctx
	ctx.factories = factorymanager.NewManager(func() servicecontext.ServiceContext { return sc }, config, wrappers)
	ctx.services = NewServiceFactory(func() servicecontext.ServiceContext { return sc }, config, options...)
	return sc
}

func (s *serviceContextImpl) Repositories() repository.Repositories {
	if s.inTransaction {
		return s.transactionalRepositories
	}
	return s.repositories
}

func (s *serviceContextImpl) Factories() service.Factories {
	return s.factories
}

func (s *serviceContextImpl) Services() service.Services {
	return s.services
}

func (s *serviceContextImpl) ExecuteInTransaction(todo func() error) error {
	if !s.inTransaction {
		// If we are not in a transaction already, start a new transaction
		var tx transaction.Transaction
		var err error
		if tx, err = s.transactionManager.BeginTransaction(); err != nil {
			log.Error(nil, map[string]interface{}{
				"err": err,
			}, "database BeginTransaction failed!")

			return errors.WithStack(err)
		}

		// Set the transaction flag to true
		s.inTransaction = true

		// Set the transactional repositories property
		s.transactionalRepositories = tx.(repository.Repositories)

		defer s.endTransaction()

		return func() error {
			errorChan := make(chan error, 1)
			txTimeout := time.After(transaction.DatabaseTransactionTimeout())

			go func() {
				defer func() {
					if err := recover(); err != nil {
						errorChan <- errors.Errorf("Unknown error: %v", err)
					}
				}()
				errorChan <- todo()
			}()

			select {
			case err := <-errorChan:
				if err != nil {
					log.Debug(nil, nil, "Rolling back the transaction...")
					tx.Rollback()
					log.Error(nil, map[string]interface{}{
						"err": err,
					}, "database transaction failed!")
					return errors.WithStack(err)
				}

				tx.Commit()
				log.Debug(nil, nil, "Commit the transaction!")
				return nil
			case <-txTimeout:
				log.Debug(nil, nil, "Rolling back the transaction...")
				tx.Rollback()
				log.Error(nil, nil, "database transaction timeout!")
				return errors.New("database transaction timeout")
			}
		}()
	} else {
		// If we are in a transaction, simply execute the passed function
		return todo()
	}
}

func (s *serviceContextImpl) endTransaction() {
	s.inTransaction = false
}

type ServiceFactory struct {
	contextProducer         servicecontext.ServiceContextProducer
	config                  *configuration.ConfigurationData
	tenantServiceFunc       func() service.TenantService       // the function to call when `TenantService()` is called on this factory
	notificationServiceFunc func() service.NotificationService // the function to call when `NotificationService()` is called on this factory
	adminConsoleServiceFunc func() service.AdminConsoleService // the function to call when `AdminConsoleService()` is called on this factory
	clusterServiceFunc      func() service.ClusterService
	authProviderServiceFunc func() service.AuthenticationProviderService
	userServiceFunc         func() service.UserService
}

// Option an option to configure the Service Factory
type Option func(f *ServiceFactory)

func WithTenantService(s service.TenantService) Option {
	return func(f *ServiceFactory) {
		f.tenantServiceFunc = func() service.TenantService {
			return s
		}
	}
}

func WithNotificationService(s service.NotificationService) Option {
	return func(f *ServiceFactory) {
		f.notificationServiceFunc = func() service.NotificationService {
			return s
		}
	}
}

func WithAdminConsoleService(s service.AdminConsoleService) Option {
	return func(f *ServiceFactory) {
		f.adminConsoleServiceFunc = func() service.AdminConsoleService {
			return s
		}
	}
}

func WithClusterService(s service.ClusterService) Option {
	return func(f *ServiceFactory) {
		f.clusterServiceFunc = func() service.ClusterService {
			return s
		}
	}
}

// WithAuthenticationProviderService overrides the default function that returns the AuthenticationProviderService,
// so that instead, a mock implementation can be used
func WithAuthenticationProviderService(s service.AuthenticationProviderService) Option {
	return func(f *ServiceFactory) {
		f.authProviderServiceFunc = func() service.AuthenticationProviderService {
			return s
		}
	}
}

// WithUserService overrides the default function that returns the UserService,
// so that instead, a mock implementation can be used
func WithUserService(s service.UserService) Option {
	return func(f *ServiceFactory) {
		f.userServiceFunc = func() service.UserService {
			return s
		}
	}
}

// NewServiceFactory returns a new ServiceFactory which can be configured with the options to replace the default implementations of some services
func NewServiceFactory(producer servicecontext.ServiceContextProducer, config *configuration.ConfigurationData, options ...Option) *ServiceFactory {
	f := &ServiceFactory{contextProducer: producer, config: config}
	// default function to return an instance of Tenant Service
	f.tenantServiceFunc = func() service.TenantService {
		return userservice.NewTenantService(f.config)
	}
	// default function to return an instance of Notification Service
	f.notificationServiceFunc = func() service.NotificationService {
		return notificationservice.NewNotificationService(f.getContext(), f.config)
	}
	// default function to return an instance of Notification Service
	f.adminConsoleServiceFunc = func() service.AdminConsoleService {
		return adminconsoleService.NewService(f.getContext(), f.config)
	}
	// default function to return an instance of Cluster Service
	f.clusterServiceFunc = func() service.ClusterService {
		return clusterservice.NewClusterService(f.getContext(), f.config)
	}
	// default function to return an instance of Auth Service
	f.authProviderServiceFunc = func() service.AuthenticationProviderService {
		return providerservice.NewAuthenticationProviderService(f.getContext(), f.config)
	}
	// default function to return an instance of User Service
	f.userServiceFunc = func() service.UserService {
		return userservice.NewUserService(f.getContext(), f.config)
	}
	log.Debug(nil, map[string]interface{}{}, "configuring a new service factory with %d option(s)", len(options))
	// and options
	for _, opt := range options {
		opt(f)
	}
	return f
}

func (f *ServiceFactory) getContext() servicecontext.ServiceContext {
	return f.contextProducer()
}

func (f *ServiceFactory) AuthenticationProviderService() service.AuthenticationProviderService {
	return f.authProviderServiceFunc()
}

func (f *ServiceFactory) InvitationService() service.InvitationService {
	return invitationservice.NewInvitationService(f.getContext(), f.config)
}

func (f *ServiceFactory) LinkService() service.LinkService {
	return providerservice.NewLinkService(f.getContext(), f.config)
}

func (f *ServiceFactory) LogoutService() service.LogoutService {
	return logoutservice.NewLogoutService(f.getContext(), f.config)
}

func (f *ServiceFactory) OrganizationService() service.OrganizationService {
	return organizationservice.NewOrganizationService(f.getContext())
}

func (f *ServiceFactory) OSOSubscriptionService() service.OSOSubscriptionService {
	return subscriptionservice.NewOSOSubscriptionService(f.getContext(), f.config)
}

func (f *ServiceFactory) PermissionService() service.PermissionService {
	return permissionservice.NewPermissionService(f.getContext())
}

func (f *ServiceFactory) PrivilegeCacheService() service.PrivilegeCacheService {
	return permissionservice.NewPrivilegeCacheService(f.getContext(), f.config)
}

func (f *ServiceFactory) ResourceService() service.ResourceService {
	return resourceservice.NewResourceService(f.getContext())
}

func (f *ServiceFactory) RoleManagementService() service.RoleManagementService {
	return roleservice.NewRoleManagementService(f.getContext())
}

func (f *ServiceFactory) TeamService() service.TeamService {
	return teamservice.NewTeamService(f.getContext())
}

func (f *ServiceFactory) TokenService() service.TokenService {
	return tokenservice.NewTokenService(f.getContext(), f.config)
}

func (f *ServiceFactory) SpaceService() service.SpaceService {
	return spaceservice.NewSpaceService(f.getContext())
}

func (f *ServiceFactory) UserService() service.UserService {
	return f.userServiceFunc()
}

func (f *ServiceFactory) UserProfileService() service.UserProfileService {
	return providerservice.NewUserProfileService(f.getContext())
}

func (f *ServiceFactory) NotificationService() service.NotificationService {
	return f.notificationServiceFunc()
}

func (f *ServiceFactory) AdminConsoleService() service.AdminConsoleService {
	return f.adminConsoleServiceFunc()
}

func (f *ServiceFactory) TenantService() service.TenantService {
	return f.tenantServiceFunc()
}

func (f *ServiceFactory) ClusterService() service.ClusterService {
	return f.clusterServiceFunc()
}

func (f *ServiceFactory) CheService() service.CheService {
	return cheservice.NewCheService(f.getContext(), f.config)
}
