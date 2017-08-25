package resource

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/jinzhu/gorm"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type Resource struct {
	gormsupport.Lifecycle

	// This is the primary key value
	ID string `sql:"type:string" gorm:"primary_key" gorm:"column:resource_id"`
	// The parent resource
	ParentResource *Resource
	// The owning identity
	Owner account.Identity
	// The resource type
	ResourceType ResourceType
	// Resource description
	Description string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m Resource) TableName() string {
	return "resource"
}

// GetLastModified returns the last modification time
func (m Resource) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormResourceRepository is the implementation of the storage interface for Resource.
type GormResourceRepository struct {
	db *gorm.DB
}

// NewResourceRepository creates a new storage type.
func NewResourceRepository(db *gorm.DB) *GormResourceRepository {
	return &GormResourceRepository{db: db}
}

// ResourceRepository represents the storage interface.
type ResourceRepository interface {
	repository.Exister
	Load(ctx context.Context, id string) (*Resource, error)
	Create(ctx context.Context, resource *Resource) error
	Save(ctx context.Context, resource *Resource) error
	Delete(ctx context.Context, id string) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Resource, error)
	IsValid(context.Context, string) bool
	Search(ctx context.Context, q string, start int, limit int) ([]Resource, int, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormResourceRepository) TableName() string {
	return "resource"
}

// CRUD Functions

// Load returns a single Resource as a Database Model
func (m *GormResourceRepository) Load(ctx context.Context, id string) (*Resource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "load"}, time.Now())

	var native Resource
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("resource", id))
	}

	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormResourceRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormResourceRepository) Create(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "create"}, time.Now())

	// If no identifier has been specified for the new resource, then generate one
	if resource.ID == "" {
		resource.ID = uuid.NewV4().String()
	}
	err := m.db.Create(resource).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ID,
			"err":         err,
		}, "unable to create the resource")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"resource_id": resource.ID,
	}, "Resource created!")
	return nil
}

// Save modifies a single record.
func (m *GormResourceRepository) Save(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "save"}, time.Now())

	obj, err := m.Load(ctx, resource.ID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ID,
			"ctx":         ctx,
			"err":         err,
		}, "unable to update the resource")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Save(resource).Error

	log.Debug(ctx, map[string]interface{}{
		"resource_id": resource.ID,
	}, "Resource saved!")

	return errs.WithStack(err)
}

// Delete removes a single record.
func (m *GormResourceRepository) Delete(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "delete"}, time.Now())

	obj := Resource{ID: id}
	db := m.db.Delete(obj)

	if db.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": id,
			"err":         db.Error,
		}, "unable to delete the resource")
		return errs.WithStack(db.Error)
	}
	if db.RowsAffected == 0 {
		return errors.NewNotFoundError("resource", id)
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_id": id,
	}, "Identity deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormResourceRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Resource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "query"}, time.Now())
	var resources []Resource
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&resources).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"resource_query": resources,
	}, "Resource query executed successfully!")

	return resources, nil
}

// ResourceFilterByResourceID is a gorm filter for a Belongs To relationship.
func ResourceFilterByID(id string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("resource_id = ?", id)
	}
}
