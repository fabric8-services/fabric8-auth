package gormapplication

import (
	"fmt"
	factorymanager "github.com/fabric8-services/fabric8-auth/application/factory/manager"
	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"

	"strconv"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	provider "github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/configuration"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// A TXIsoLevel specifies the characteristics of the transaction
// See https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
type TXIsoLevel int8

const (
	// TXIsoLevelDefault doesn't specify any transaction isolation level, instead the connection
	// based setting will be used.
	TXIsoLevelDefault TXIsoLevel = iota

	// TXIsoLevelReadCommitted means "A statement can only see rows committed before it began. This is the default."
	TXIsoLevelReadCommitted

	// TXIsoLevelRepeatableRead means "All statements of the current transaction can only see rows committed before the
	// first query or data-modification statement was executed in this transaction."
	TXIsoLevelRepeatableRead

	// TXIsoLevelSerializable means "All statements of the current transaction can only see rows committed
	// before the first query or data-modification statement was executed in this transaction.
	// If a pattern of reads and writes among concurrent serializable transactions would create a
	// situation which could not have occurred for any serial (one-at-a-time) execution of those
	// transactions, one of them will be rolled back with a serialization_failure error."
	TXIsoLevelSerializable
)

//var x application.Application = &GormDB{}

//var y application.Application = &GormTransaction{}

func NewGormDB(db *gorm.DB, config *configuration.ConfigurationData, options ...factory.Option) *GormDB {
	g := new(GormDB)
	g.db = db.Set("gorm:save_associations", false)
	g.txIsoLevel = ""
	g.serviceContext = factory.NewServiceContext(g, g, config, options...)
	return g
}

// GormBase is a base struct for gorm implementations of db & transaction
type GormBase struct {
	db *gorm.DB
}

// GormTransaction implements the Transaction interface methods for committing or rolling back a transaction
type GormTransaction struct {
	GormBase
}

// GormDB implements the TransactionManager interface methods for initiating a new transaction
type GormDB struct {
	GormBase
	txIsoLevel     string
	serviceContext context.ServiceContext
}

//----------------------------------------------------------------------------------------------------------------------
//
// Repositories
//
//----------------------------------------------------------------------------------------------------------------------

// Identities creates new Identity repository
func (g *GormBase) Identities() account.IdentityRepository {
	return account.NewIdentityRepository(g.db)
}

// Users creates new user repository
func (g *GormBase) Users() account.UserRepository {
	return account.NewUserRepository(g.db)
}

// OauthStates returns an oauth state reference repository
func (g *GormBase) OauthStates() provider.OauthStateReferenceRepository {
	return provider.NewOauthStateReferenceRepository(g.db)
}

// ExternalTokens returns an ExternalTokens repository
func (g *GormBase) ExternalTokens() token.ExternalTokenRepository {
	return token.NewExternalTokenRepository(g.db)
}

// VerificationCodes returns an VerificationCodes repository
func (g *GormBase) VerificationCodes() account.VerificationCodeRepository {
	return account.NewVerificationCodeRepository(g.db)
}

func (g *GormBase) InvitationRepository() invitation.InvitationRepository {
	return invitation.NewInvitationRepository(g.db)
}

func (g *GormBase) ResourceRepository() resource.ResourceRepository {
	return resource.NewResourceRepository(g.db)
}

func (g *GormBase) ResourceTypeRepository() resourcetype.ResourceTypeRepository {
	return resourcetype.NewResourceTypeRepository(g.db)
}

func (g *GormBase) ResourceTypeScopeRepository() resourcetype.ResourceTypeScopeRepository {
	return resourcetype.NewResourceTypeScopeRepository(g.db)
}

func (g *GormBase) RoleRepository() role.RoleRepository {
	return role.NewRoleRepository(g.db)
}

func (g *GormBase) IdentityRoleRepository() role.IdentityRoleRepository {
	return role.NewIdentityRoleRepository(g.db)
}

func (g *GormBase) DefaultRoleMappingRepository() role.DefaultRoleMappingRepository {
	return role.NewDefaultRoleMappingRepository(g.db)
}

func (g *GormBase) RoleMappingRepository() role.RoleMappingRepository {
	return role.NewRoleMappingRepository(g.db)
}

func (g *GormBase) TokenRepository() token.TokenRepository {
	return token.NewTokenRepository(g.db)
}

func (g *GormBase) PrivilegeCacheRepository() permission.PrivilegeCacheRepository {
	return permission.NewPrivilegeCacheRepository(g.db)
}

//----------------------------------------------------------------------------------------------------------------------
//
// Services
//
//----------------------------------------------------------------------------------------------------------------------

func (g *GormDB) AuthenticationProviderService() service.AuthenticationProviderService {
	return g.serviceContext.Services().AuthenticationProviderService()
}

func (g *GormDB) InvitationService() service.InvitationService {
	return g.serviceContext.Services().InvitationService()
}

func (g *GormDB) LinkService() service.LinkService {
	return g.serviceContext.Services().LinkService()
}

func (g *GormDB) LogoutService() service.LogoutService {
	return g.serviceContext.Services().LogoutService()
}

func (g *GormDB) OSOSubscriptionService() service.OSOSubscriptionService {
	return g.serviceContext.Services().OSOSubscriptionService()
}

func (g *GormDB) OrganizationService() service.OrganizationService {
	return g.serviceContext.Services().OrganizationService()
}

func (g *GormDB) PermissionService() service.PermissionService {
	return g.serviceContext.Services().PermissionService()
}

func (g *GormDB) PrivilegeCacheService() service.PrivilegeCacheService {
	return g.serviceContext.Services().PrivilegeCacheService()
}

func (g *GormDB) RoleManagementService() service.RoleManagementService {
	return g.serviceContext.Services().RoleManagementService()
}

func (g *GormDB) TeamService() service.TeamService {
	return g.serviceContext.Services().TeamService()
}

func (g *GormDB) ResourceService() service.ResourceService {
	return g.serviceContext.Services().ResourceService()
}

func (g *GormDB) SpaceService() service.SpaceService {
	return g.serviceContext.Services().SpaceService()
}

func (g *GormDB) TokenService() service.TokenService {
	return g.serviceContext.Services().TokenService()
}

func (g *GormDB) UserService() service.UserService {
	return g.serviceContext.Services().UserService()
}

func (g *GormDB) UserProfileService() service.UserProfileService {
	return g.serviceContext.Services().UserProfileService()
}

func (g *GormDB) NotificationService() service.NotificationService {
	return g.serviceContext.Services().NotificationService()
}

func (g *GormDB) WITService() service.WITService {
	return g.serviceContext.Services().WITService()
}

func (g *GormDB) ClusterService() service.ClusterService {
	return g.serviceContext.Services().ClusterService()
}

//----------------------------------------------------------------------------------------------------------------------
//
// Factories
//
//----------------------------------------------------------------------------------------------------------------------

func (g *GormDB) IdentityProviderFactory() service.IdentityProviderFactory {
	return g.serviceContext.Factories().IdentityProviderFactory()
}

func (g *GormDB) LinkingProviderFactory() service.LinkingProviderFactory {
	return g.serviceContext.Factories().LinkingProviderFactory()
}

func (g *GormDB) WrapFactory(identifier string, constructor wrapper.FactoryWrapperConstructor, initializer wrapper.FactoryWrapperInitializer) {
	g.serviceContext.Factories().(factorymanager.FactoryManager).WrapFactory(identifier, constructor, initializer)
}

func (g *GormDB) ResetFactories() {
	g.serviceContext.Factories().(factorymanager.FactoryManager).ResetFactories()
}

//----------------------------------------------------------------------------------------------------------------------
//
// Misc
//
//----------------------------------------------------------------------------------------------------------------------

func (g *GormBase) DB() *gorm.DB {
	return g.db
}

func (g *GormDB) setTransactionIsolationLevel(level string) {
	g.txIsoLevel = level
}

// SetTransactionIsolationLevel sets the isolation level for
// See also https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
func (g *GormDB) SetTransactionIsolationLevel(level TXIsoLevel) error {
	switch level {
	case TXIsoLevelReadCommitted:
		g.txIsoLevel = "READ COMMITTED"
	case TXIsoLevelRepeatableRead:
		g.txIsoLevel = "REPEATABLE READ"
	case TXIsoLevelSerializable:
		g.txIsoLevel = "SERIALIZABLE"
	case TXIsoLevelDefault:
		g.txIsoLevel = ""
	default:
		return fmt.Errorf("Unknown transaction isolation level: " + strconv.FormatInt(int64(level), 10))
	}
	return nil
}

// BeginTransaction initiates a new transaction
func (g *GormDB) BeginTransaction() (transaction.Transaction, error) {
	tx := g.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	if len(g.txIsoLevel) != 0 {
		tx := tx.Exec(fmt.Sprintf("set transaction isolation level %s", g.txIsoLevel))
		if tx.Error != nil {
			return nil, tx.Error
		}
		return &GormTransaction{GormBase{tx}}, nil
	}
	return &GormTransaction{GormBase{tx}}, nil
}

// Commit commits the current transaction
func (g *GormTransaction) Commit() error {
	err := g.db.Commit().Error
	g.db = nil
	return errors.WithStack(err)
}

// Rollback rolls back current transaction
func (g *GormTransaction) Rollback() error {
	err := g.db.Rollback().Error
	g.db = nil
	return errors.WithStack(err)
}
