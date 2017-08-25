package role

import (
	"context"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"

	uuid "github.com/satori/go.uuid"
	errs "github.com/pkg/errors"
)

type RoleScope struct {
	gormsupport.Lifecycle

	Scope resource.ResourceTypeScope `gorm:"primary_key;ForeignKey:ScopeID;AssociationForeignKey:ResourceTypeScopeID"`
	ScopeID uuid.UUID

	Role Role `gorm:"primary_key;ForeignKey:RoleID;AssociationForeignKey:RoleID"`
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

// NewRoleRepository creates a new storage type.
func NewRoleScopeRepository(db *gorm.DB) RoleScopeRepository {
	return &GormRoleScopeRepository{db: db}
}

// RoleScopeRepository represents the storage interface.
type RoleScopeRepository interface {
	CheckExists(ctx context.Context, resourceTypeScopeID string, roleID string) (bool, error)
	Load(ctx context.Context, ScopeID uuid.UUID, RoleID uuid.UUID) (*RoleScope, error)
	Create(ctx context.Context, u *RoleScope) error
	Save(ctx context.Context, u *RoleScope) error
	List(ctx context.Context) ([]RoleScope, error)
	Delete(ctx context.Context, resourceTypeScopeID uuid.UUID, roleID uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]RoleScope, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleScopeRepository) TableName() string {
	return "role_scope"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormRoleScopeRepository) CheckExists(ctx context.Context, resourceTypeScopeID string, roleID string) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				resource_type_scope_id=$1
				AND role_id=$2
				AND deleted_at IS NULL
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, resourceTypeScopeID, roleID).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), resourceTypeScopeID + "," + roleID)
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

// CRUD Functions

// Load returns a single RoleScope as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormRoleScopeRepository) Load(ctx context.Context, ScopeID uuid.UUID, RoleID uuid.UUID) (*RoleScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "load"}, time.Now())
	var native RoleScope
	err := m.db.Table(m.TableName()).Preload("Scope,Role").Where("scope_id = ? and role_id = ?",
		ScopeID.String(), RoleID.String()).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("role_scope", ScopeID.String() + "," + RoleID.String())
	}
	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormRoleScopeRepository) Create(ctx context.Context, u *RoleScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "create"}, time.Now())
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": u.Scope.ResourceTypeScopeID,
			"role_id": u.Role.RoleID,
			"err": err,
		}, "unable to create the role scope")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": u.Scope.ResourceTypeScopeID,
		"role_id": u.Role.RoleID,
	}, "Role scope created!")
	return nil
}

// Save modifies a single record
func (m *GormRoleScopeRepository) Save(ctx context.Context, model *RoleScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "save"}, time.Now())

	obj, err := m.Load(ctx, model.Scope.ResourceTypeScopeID, model.Role.RoleID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": model.Scope.ResourceTypeScopeID,
			"role_id": model.Role.RoleID,
			"err": err,
		}, "unable to update role scope")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": model.Scope.ResourceTypeScopeID,
		"role_id": model.Role.RoleID,
	}, "Role scope saved!")
	return nil
}

// Delete removes a single record.
func (m *GormRoleScopeRepository) Delete(ctx context.Context, resourceTypeScopeID uuid.UUID, roleID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "delete"}, time.Now())

	obj := RoleScope{Scope:resource.ResourceTypeScope{ResourceTypeScopeID: resourceTypeScopeID}, Role: Role{RoleID: roleID}}

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": resourceTypeScopeID,
			"role_id": roleID,
			"err": err,
		}, "unable to delete the role scope")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": resourceTypeScopeID,
		"role_id": roleID,
	}, "Role scope deleted!")

	return nil
}

// List returns all role scopes
func (m *GormRoleScopeRepository) List(ctx context.Context) ([]RoleScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "list"}, time.Now())
	var rows []RoleScope

	err := m.db.Model(&resource.ResourceType{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Query expose an open ended Query model
func (m *GormRoleScopeRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]RoleScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_scope", "query"}, time.Now())
	var objs []RoleScope

	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&objs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	log.Debug(nil, map[string]interface{}{
		"role_scope_list": objs,
	}, "Role scope query successfully executed!")

	return objs, nil
}

// RoleScopeFilterByID is a gorm filter for Role ID.
func RoleScopeFilterByID(resourceTypeScopeID uuid.UUID, roleID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("resource_type_scope_id = ? and role_id = ?", resourceTypeScopeID, roleID)
	}
}