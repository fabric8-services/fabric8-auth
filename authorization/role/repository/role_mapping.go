package repository

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository/base"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// RoleMapping is used to define a role mapping, allowing an identity with a certain role for the resource to
// automatically inherit the privileges of another role for certain types of descendent resources.
// For example, a role mapping for an organization resource that maps from the organization:admin role (FromRole)
// to the space:admin role (ToRole) means that any identities that are assigned the admin role for the organization
// also inherit the admin role for any space resources that are under that organization.
type RoleMapping struct {
	gormsupport.Lifecycle

	// This is the primary key value
	RoleMappingID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:role_mapping_id"`
	// The resource that this role mapping applies to
	Resource resource.Resource `gorm:"ForeignKey:ResourceID;AssociationForeignKey:ResourceID"`
	// The foreign key value for Resource
	ResourceID string
	// The role that is being mapped from
	FromRole Role `gorm:"ForeignKey:RoleID;AssociationForeignKey:FromRoleID"`
	// The foreign key value for FromRole
	FromRoleID uuid.UUID
	// The role that is being mapped to
	ToRole Role `gorm:"ForeignKey:RoleID;AssociationForeignKey:ToRoleID"`
	// The foreign key value for ToRole
	ToRoleID uuid.UUID
}

func (m RoleMapping) TableName() string {
	return "role_mapping"
}

// GetLastModified returns the last modification time
func (m RoleMapping) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormRoleRepository is the implementation of the storage interface for Role.
type GormRoleMappingRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates a new storage type.
func NewRoleMappingRepository(db *gorm.DB) RoleMappingRepository {
	return &GormRoleMappingRepository{db: db}
}

// RoleMappingRepository represents the storage interface.
type RoleMappingRepository interface {
	CheckExists(ctx context.Context, id uuid.UUID) error
	Load(ctx context.Context, ID uuid.UUID) (*RoleMapping, error)
	Create(ctx context.Context, u *RoleMapping) error
	Save(ctx context.Context, u *RoleMapping) error
	List(ctx context.Context) ([]RoleMapping, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	DeleteForResource(ctx context.Context, resourceID string) error
	FindForResource(ctx context.Context, resourceID string) ([]RoleMapping, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleMappingRepository) TableName() string {
	return "role_mapping"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormRoleMappingRepository) CheckExists(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "exists"}, time.Now())
	return base.CheckExistsWithCustomIDColumn(ctx, m.db, m.TableName(), "role_mapping_id", id.String())
}

// CRUD Functions

// Load returns a single RoleMapping as a Database Model
func (m *GormRoleMappingRepository) Load(ctx context.Context, id uuid.UUID) (*RoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "load"}, time.Now())
	var native RoleMapping
	err := m.db.Table(m.TableName()).Preload("FromRole").Preload("ToRole").Where("role_mapping_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("role_mapping", id.String())
	}
	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormRoleMappingRepository) Create(ctx context.Context, u *RoleMapping) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "create"}, time.Now())
	if u.RoleMappingID == uuid.Nil {
		u.RoleMappingID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_mapping_id": u.RoleMappingID,
			"err":             err,
		}, "unable to create the role mapping")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"role_mapping_id": u.RoleMappingID,
	}, "Role mapping created!")
	return nil
}

// Save modifies a single record
func (m *GormRoleMappingRepository) Save(ctx context.Context, model *RoleMapping) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "save"}, time.Now())

	obj, err := m.Load(ctx, model.RoleMappingID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_mapping_id": model.RoleMappingID,
			"err":             err,
		}, "unable to update role mapping")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"role_mapping_id": model.RoleMappingID,
	}, "Role mapping saved!")
	return nil
}

// List returns all role mappings
func (m *GormRoleMappingRepository) List(ctx context.Context) ([]RoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "list"}, time.Now())
	var rows []RoleMapping

	err := m.db.Model(&RoleMapping{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Delete removes a single record.
func (m *GormRoleMappingRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "delete"}, time.Now())

	obj := RoleMapping{RoleMappingID: id}

	result := m.db.Delete(&obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"role_mapping_id": id,
			"err":             result.Error,
		}, "unable to delete the role mapping")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("role_mapping", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"role_mapping_id": id,
	}, "Role mapping deleted!")

	return nil
}

// DeleteForResource deletes all role mappings for the given resource ID
// No error is returned if no role mappings found
func (m *GormRoleMappingRepository) DeleteForResource(ctx context.Context, resourceID string) error {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "deleteForResource"}, time.Now())

	err := m.db.Table(m.TableName()).Where("resource_id = ?", resourceID).Delete(nil).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return errs.WithStack(err)
	}
	return nil
}

func (m *GormRoleMappingRepository) FindForResource(ctx context.Context, resourceID string) ([]RoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "findForResource"}, time.Now())

	var rows []RoleMapping

	err := m.db.Model(&RoleMapping{}).Where("resource_id = ?", resourceID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}
