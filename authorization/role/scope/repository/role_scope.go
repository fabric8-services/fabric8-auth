package repository

import (
	"context"
	"time"

	resourceTypeScope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	errs "github.com/pkg/errors"
)

// RoleScope defines the association between a resource type's scope(s) and a resource type's role.
type RoleScope struct {
	gormsupport.Lifecycle

	// The associated scope
	ResourceTypeScope resourceTypeScope.ResourceTypeScope `gorm:"ForeignKey:ResourceTypeScopeID"`

	// The foreign key value for ResourceTypeScopeID
	ResourceTypeScopeID uuid.UUID `gorm:"column:scope_id"`

	// The associated role
	Role role.Role `gorm:"ForeignKey:RoleID"`

	// The foreign key value for RoleID
	RoleID uuid.UUID
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m RoleScope) TableName() string {
	return "role_scope"
}

// GetLastModified returns the last modification time
func (m RoleScope) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormRoleScopeRepository is the implementation of the storage interface for RoleScope.
type GormRoleScopeRepository struct {
	db *gorm.DB
}

// NewRoleScopeRepository creates a new storage type.
func NewRoleScopeRepository(db *gorm.DB) RoleScopeRepository {
	return &GormRoleScopeRepository{db: db}
}

// RoleScopeRepository represents the storage interface.
type RoleScopeRepository interface {
	LoadByScope(ctx context.Context, ID uuid.UUID) ([]RoleScope, error)
	LoadByRole(ctx context.Context, ID uuid.UUID) ([]RoleScope, error)
	Create(ctx context.Context, roleScope *RoleScope) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]RoleScope, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleScopeRepository) TableName() string {
	return "role_scope"
}

// Create creates a new RoleScope
func (m *GormRoleScopeRepository) Create(ctx context.Context, roleScope *RoleScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "create"}, time.Now())
	err := m.db.Create(roleScope).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": roleScope.ResourceTypeScope.ResourceTypeScopeID,
			"role_id":                roleScope.Role.RoleID,
			"err":                    err,
		}, "unable to create the role scope")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"resource_scope_id": roleScope.ResourceTypeScope.ResourceTypeScopeID,
		"role_id":           roleScope.Role.RoleID,
	}, "Role Scope created!")
	return nil
}

//LoadByScope loads a 'role & scope assocation' by the scope ID
func (m *GormRoleScopeRepository) LoadByScope(ctx context.Context, ID uuid.UUID) ([]RoleScope, error) {
	return m.Query(RoleScopeFilterByScope(ID))
}

//LoadByRole loads a 'role & scope assocation' by the role ID
func (m *GormRoleScopeRepository) LoadByRole(ctx context.Context, ID uuid.UUID) ([]RoleScope, error) {
	return m.Query(RoleScopeFilterByRole(ID))
}

// Query expose an open ended Query model
func (m *GormRoleScopeRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]RoleScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "query"}, time.Now())
	var roleScopes []RoleScope
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&roleScopes).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"role_scopes": roleScopes,
	}, "Role Scope query executed successfully!")

	return roleScopes, nil
}

// RoleScopeFilterByScope is a gorm filter by 'scope_id'
func RoleScopeFilterByScope(id uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("scope_id = ?", id)
	}
}

// RoleScopeFilterByRole is a gorm filter by 'role'
func RoleScopeFilterByRole(id uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("role_id = ?", id)
	}
}
