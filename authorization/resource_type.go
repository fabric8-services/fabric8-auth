package authorization

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/application/repository"

	"github.com/satori/go.uuid"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"

	errs "github.com/pkg/errors"
)

type ResourceType struct {
	gormsupport.Lifecycle

	ResourceTypeID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:resource_type_id"`
	// The resource type name
	Name string
	// The resource type description
	Description string
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
	repository.Exister
	Load(ctx context.Context, ID uuid.UUID) (*ResourceType, error)
	Create(ctx context.Context, u *ResourceType) error
	Save(ctx context.Context, u *ResourceType) error
	List(ctx context.Context) ([]ResourceType, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ResourceType, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormResourceTypeRepository) TableName() string {
	return "resource_type"
}

// CRUD Functions

// Load returns a single ResourceType as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormResourceTypeRepository) Load(ctx context.Context, id uuid.UUID) (*ResourceType, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "load"}, time.Now())
	var native ResourceType
	err := m.db.Table(m.TableName()).Where("resource_type_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("resource_type_scope", id.String())
	}
	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormResourceTypeRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
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
	}, "Resource Type created!")
	return nil
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

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_id": id,
			"err":              err,
		}, "unable to delete the resource type")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_id": id,
	}, "Resource type deleted!")

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

// Query expose an open ended Query model
func (m *GormResourceTypeRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ResourceType, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type", "query"}, time.Now())
	var objs []ResourceType

	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&objs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	log.Debug(nil, map[string]interface{}{
		"resource_type_list": objs,
	}, "Resource type query successfully executed!")

	return objs, nil
}

// ResourceTypeFilterByID is a gorm filter for Resource Type ID.
func ResourceTypeFilterByID(resourceTypeID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("resource_type_id = ?", resourceTypeID)
	}
}
