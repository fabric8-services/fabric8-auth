package repository

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type ResourceType struct {
	gormsupport.Lifecycle

	ResourceTypeID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:resource_type_id"`
	// The resource type name
	Name string

	DefaultRoleID *uuid.UUID `sql:"type:string" gorm:"column:default_role_id"`
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ResourceType) TableName() string {
	return "resource_type"
}

// GetLastModified returns the last modification time
func (m ResourceType) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormResourceTypeRepository is the implementation of the storage interface for ResourceType.
type GormResourceTypeRepository struct {
	db *gorm.DB
}

// NewResourceTypeRepository creates a new storage type.
func NewResourceTypeRepository(db *gorm.DB) ResourceTypeRepository {
	return &GormResourceTypeRepository{db: db}
}

// ResourceTypeRepository represents the storage interface.
type ResourceTypeRepository interface {
	Create(ctx context.Context, u *ResourceType) error
	Lookup(ctx context.Context, name string) (*ResourceType, error)
	List(ctx context.Context) ([]ResourceType, error)
	Save(ctx context.Context, u *ResourceType) error
	Delete(ctx context.Context, ID uuid.UUID) error
	Load(ctx context.Context, ID uuid.UUID) (*ResourceType, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormResourceTypeRepository) TableName() string {
	return "resource_type"
}

// Query Functions

// Lookup looks up the ResourceType record with the specified name.  If there is no such record, then
// a gorm.ErrRecordNotFound error will be returned.
func (m *GormResourceTypeRepository) Lookup(ctx context.Context, name string) (*ResourceType, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "lookupOrCreate"}, time.Now())

	var native ResourceType
	err := m.db.Table(m.TableName()).Where("name = ?", name).First(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundErrorWithKey("resource_type", "name", name)
	}
	return &native, err
}

// Create creates a new record.
func (m *GormResourceTypeRepository) Create(ctx context.Context, u *ResourceType) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "create"}, time.Now())
	if u.ResourceTypeID == uuid.Nil {
		u.ResourceTypeID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_id": u.ResourceTypeID,
			"err":              err,
		}, "unable to create the resource type")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"resource_type_id": u.ResourceTypeID,
	}, "Resource Type Scope created!")
	return nil
}

// List return all resource types
func (m *GormResourceTypeRepository) List(ctx context.Context) ([]ResourceType, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "list"}, time.Now())
	var rows []ResourceType

	err := m.db.Model(&ResourceType{}).Order("name").Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Save modifies a single record
func (m *GormResourceTypeRepository) Save(ctx context.Context, model *ResourceType) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ResourceTypeID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_id": model.ResourceTypeID,
			"err":              err,
		}, "unable to update resource type")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_id": model.ResourceTypeID,
	}, "Resource Type saved!")
	return nil
}

// Delete removes a single record.
func (m *GormResourceTypeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "delete"}, time.Now())

	obj := ResourceType{ResourceTypeID: id}

	result := m.db.Delete(&obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_id": id,
			"err":              result.Error,
		}, "unable to delete the resource type")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("resource_type", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_id": id,
	}, "Resource type deleted!")

	return nil
}

// Load returns a single ResourceType as a Database Model
func (m *GormResourceTypeRepository) Load(ctx context.Context, id uuid.UUID) (*ResourceType, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "load"}, time.Now())
	var native ResourceType
	err := m.db.Table(m.TableName()).Where("resource_type_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("resource_type", id.String())
	}
	return &native, errs.WithStack(err)
}
