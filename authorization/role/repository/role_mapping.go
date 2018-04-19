package repository

import (
	"context"
	"fmt"
	"time"

	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

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
	CheckExists(ctx context.Context, ID uuid.UUID) (bool, error)
	Load(ctx context.Context, ID uuid.UUID) (*RoleMapping, error)
	Create(ctx context.Context, u *RoleMapping) error
	Save(ctx context.Context, u *RoleMapping) error
	List(ctx context.Context) ([]RoleMapping, error)
	Delete(ctx context.Context, ID uuid.UUID) error
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleMappingRepository) TableName() string {
	return "role_mapping"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormRoleMappingRepository) CheckExists(ctx context.Context, ID uuid.UUID) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role_mapping", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				role_mapping_id=$1
				AND deleted_at IS NULL
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, ID.String()).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), ID.String())
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
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

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_mapping_id": id,
			"err":             err,
		}, "unable to delete the role mapping")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"role_mapping_id": id,
	}, "Role mapping deleted!")

	return nil
}
