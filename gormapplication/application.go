package gormapplication

import (
	"fmt"
	"strconv"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/auth"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/fabric8-services/fabric8-auth/token/provider"

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

func NewGormDB(db *gorm.DB) *GormDB {
	val := new(GormDB)
	val.db = db.Set("gorm:save_associations", false)
	val.txIsoLevel = ""
	val.serviceFactory = factory.NewServiceFactory(func() *context.ServiceContext {
		ctx := factory.NewServiceContext(val, val)
		return &ctx
	})
	return val
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
	serviceFactory *factory.ServiceFactory
}

func (g *GormBase) SpaceResources() space.ResourceRepository {
	return space.NewResourceRepository(g.db)
}

// Identities creates new Identity repository
func (g *GormBase) Identities() account.IdentityRepository {
	return account.NewIdentityRepository(g.db)
}

// Users creates new user repository
func (g *GormBase) Users() account.UserRepository {
	return account.NewUserRepository(g.db)
}

// OauthStates returns an oauth state reference repository
func (g *GormBase) OauthStates() auth.OauthStateReferenceRepository {
	return auth.NewOauthStateReferenceRepository(g.db)
}

// ExternalTokens returns an ExternalTokens repository
func (g *GormBase) ExternalTokens() provider.ExternalTokenRepository {
	return provider.NewExternalTokenRepository(g.db)
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

func (g *GormDB) InvitationService() service.InvitationService {
	return g.serviceFactory.InvitationService()
}

func (g *GormDB) OrganizationService() service.OrganizationService {
	return g.serviceFactory.OrganizationService()
}

func (g *GormDB) PermissionService() service.PermissionService {
	return g.serviceFactory.PermissionService()
}

func (g *GormDB) RoleManagementService() service.RoleManagementService {
	return g.serviceFactory.RoleManagementService()
}

func (g *GormDB) TeamService() service.TeamService {
	return g.serviceFactory.TeamService()
}

func (g *GormDB) ResourceService() service.ResourceService {
	return g.serviceFactory.ResourceService()
}

func (g *GormDB) SpaceService() service.SpaceService {
	return g.serviceFactory.SpaceService()
}

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
