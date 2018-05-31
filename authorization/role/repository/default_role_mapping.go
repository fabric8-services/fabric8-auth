package repository

import (
	"context"
	"fmt"
	"time"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// DefaultRoleMapping is used to define a rule for creating role mappings when registering new resources.  A role
// mapping allows an identity with a certain role for the resource to automatically inherit the privileges of another
// role for certain types of descendent resources.  For example, a default role mapping rule that maps from the
// organization:admin role (FromRole) to the space:admin role (ToRole) for an organization (ResourceType) resource
// means that any identities that are assigned the admin role for the newly created organization, also inherit the
// admin role for any space resources that are under that organization.
type DefaultRoleMapping struct {
	gormsupport.Lifecycle

	// This is the primary key value
	DefaultRoleMappingID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:default_role_mapping_id"`
	// The resource type that this role mapping applies to
	ResourceType resourcetype.ResourceType `gorm:"ForeignKey:ResourceTypeID;AssociationForeignKey:ResourceTypeID"`
	// The foreign key value for ResourceType
	ResourceTypeID uuid.UUID
	// The role that is being mapped from
	FromRole Role `gorm:"ForeignKey:RoleID;AssociationForeignKey:FromRoleID"`
	// The foreign key value for FromRole
	FromRoleID uuid.UUID
	// The role that is being mapped to
	ToRole Role `gorm:"ForeignKey:RoleID;AssociationForeignKey:ToRoleID"`
	// The foreign key value for ToRole
	ToRoleID uuid.UUID
}

func (m DefaultRoleMapping) TableName() string {
	return "default_role_mapping"
}

// GetLastModified returns the last modification time
func (m DefaultRoleMapping) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormDefaultRoleRepository is the implementation of the storage interface for Role.
type GormDefaultRoleMappingRepository struct {
	db *gorm.DB
}

// NewDefaultRoleMappingRepository creates a new storage type.
func NewDefaultRoleMappingRepository(db *gorm.DB) DefaultRoleMappingRepository {
	return &GormDefaultRoleMappingRepository{db: db}
}

// DefaultRoleMappingRepository represents the storage interface.
type DefaultRoleMappingRepository interface {
	CheckExists(ctx context.Context, ID uuid.UUID) (bool, error)
	Load(ctx context.Context, ID uuid.UUID) (*DefaultRoleMapping, error)
	Create(ctx context.Context, u *DefaultRoleMapping) error
	Save(ctx context.Context, u *DefaultRoleMapping) error
	List(ctx context.Context) ([]DefaultRoleMapping, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	FindForResourceType(ctx context.Context, resourceTypeID uuid.UUID) ([]DefaultRoleMapping, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormDefaultRoleMappingRepository) TableName() string {
	return "default_role_mapping"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormDefaultRoleMappingRepository) CheckExists(ctx context.Context, ID uuid.UUID) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				default_role_mapping_id=$1
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
func (m *GormDefaultRoleMappingRepository) Load(ctx context.Context, id uuid.UUID) (*DefaultRoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "load"}, time.Now())
	var native DefaultRoleMapping
	err := m.db.Table(m.TableName()).
		Preload("ResourceType").
		Preload("FromRole").
		Preload("ToRole").
		Where("default_role_mapping_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("default_role_mapping", id.String())
	}
	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormDefaultRoleMappingRepository) Create(ctx context.Context, u *DefaultRoleMapping) error {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "create"}, time.Now())
	if u.DefaultRoleMappingID == uuid.Nil {
		u.DefaultRoleMappingID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"default_role_mapping_id": u.DefaultRoleMappingID,
			"err": err,
		}, "unable to create the default role mapping")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"default_role_mapping_id": u.DefaultRoleMappingID,
	}, "Default role mapping created!")
	return nil
}

// Save modifies a single record
func (m *GormDefaultRoleMappingRepository) Save(ctx context.Context, model *DefaultRoleMapping) error {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "save"}, time.Now())

	obj, err := m.Load(ctx, model.DefaultRoleMappingID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"default_role_mapping_id": model.DefaultRoleMappingID,
			"err": err,
		}, "unable to update default role mapping")
		return errs.WithStack(err)
	}
	// Select("ResourceTypeID", "FromRoleID", "ToRoleID").Updates(model)
	err = m.db.Model(obj).Save(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"default_role_mapping_id": model.DefaultRoleMappingID,
	}, "Default role mapping saved!")
	return nil
}

// List returns all default role mappings
func (m *GormDefaultRoleMappingRepository) List(ctx context.Context) ([]DefaultRoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "list"}, time.Now())
	var rows []DefaultRoleMapping

	err := m.db.Model(&DefaultRoleMapping{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Delete removes a single record.
func (m *GormDefaultRoleMappingRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "delete"}, time.Now())

	obj := DefaultRoleMapping{DefaultRoleMappingID: id}

	result := m.db.Delete(&obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"default_role_mapping_id": id,
			"err": result.Error,
		}, "unable to delete the default role mapping")
		return errs.WithStack(result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("default_role_mapping", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"default_role_mapping_id": id,
	}, "Default role mapping deleted!")

	return nil
}

func (m *GormDefaultRoleMappingRepository) FindForResourceType(ctx context.Context, resourceTypeID uuid.UUID) ([]DefaultRoleMapping, error) {
	defer goa.MeasureSince([]string{"goa", "db", "default_role_mapping", "FindForResourceType"}, time.Now())

	var rows []DefaultRoleMapping

	err := m.db.Model(&DefaultRoleMapping{}).Where("resource_type_id = ?", resourceTypeID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}
