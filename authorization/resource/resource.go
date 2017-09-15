package resource

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/jinzhu/gorm"

	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type Resource struct {
	gormsupport.Lifecycle

	// This is the primary key value
	ResourceID string `sql:"type:string" gorm:"primary_key" gorm:"column:resource_id"`
	// The parent resource
	ParentResource *Resource
	// The owning identity
	Owner account.Identity
	// The resource type
	ResourceType ResourceType
	// Resource description
	Description *string
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
func NewResourceRepository(db *gorm.DB) ResourceRepository {
	return &GormResourceRepository{db: db}
}

// ResourceRepository represents the storage interface.
type ResourceRepository interface {
	repository.Exister
	Load(ctx context.Context, id string) (*Resource, error)
	Create(ctx context.Context, resource *Resource) error
	Save(ctx context.Context, resource *Resource) error
	Delete(ctx context.Context, id string) error
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

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				resource_id=$1
				AND deleted_at IS NULL
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, id).Scan(&exists)
	if err == nil && !exists {
		return errors.NewNotFoundError(m.TableName(), id)
	}
	if err != nil {
		return errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return nil
}

// Create creates a new record.
func (m *GormResourceRepository) Create(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "create"}, time.Now())

	// If no identifier has been specified for the new resource, then generate one
	if resource.ResourceID == "" {
		resource.ResourceID = uuid.NewV4().String()
	}
	err := m.db.Create(resource).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ResourceID,
			"err":         err,
		}, "unable to create the resource")
		fmt.Printf("Failed!!!! %v\n", err)
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"resource_id": resource.ResourceID,
	}, "Resource created!")
	return nil
}

// Save modifies a single record.
func (m *GormResourceRepository) Save(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "save"}, time.Now())

	obj, err := m.Load(ctx, resource.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ResourceID,
			"err":         err,
		}, "unable to update the resource")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Save(resource).Error

	log.Debug(ctx, map[string]interface{}{
		"resource_id": resource.ResourceID,
	}, "Resource saved!")

	return errs.WithStack(err)
}

// Delete removes a single record.
func (m *GormResourceRepository) Delete(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "delete"}, time.Now())

	obj := Resource{ResourceID: id}
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
		"resource_id": id,
	}, "Resource deleted!")

	return nil
}
