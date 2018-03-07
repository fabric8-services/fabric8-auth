package repository

import (
	"context"
	"time"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	"fmt"
	errs "github.com/pkg/errors"
)

type ResourceTypeScope struct {
	gormsupport.Lifecycle

	// This is the primary key value
	ResourceTypeScopeID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:resource_type_scope_id"`
	// The resource type that this scope belongs to
	ResourceType resourcetype.ResourceType `gorm:"ForeignKey:ResourceTypeID;AssociationForeignKey:ResourceTypeID"`
	// The foreign key value for ResourceType
	ResourceTypeID uuid.UUID
	// The name of this scope
	Name string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ResourceTypeScope) TableName() string {
	return "resource_type_scope"
}

// GetLastModified returns the last modification time
func (m ResourceTypeScope) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormResourceTypeScopeRepository is the implementation of the storage interface for ResourceTypeScope.
type GormResourceTypeScopeRepository struct {
	db *gorm.DB
}

// NewResourceTypeScopeRepository creates a new storage type.
func NewResourceTypeScopeRepository(db *gorm.DB) ResourceTypeScopeRepository {
	return &GormResourceTypeScopeRepository{db: db}
}

// ResourceTypeScopeRepository represents the storage interface.
type ResourceTypeScopeRepository interface {
	Create(ctx context.Context, resourceTypeScope *ResourceTypeScope) error
	CheckExists(ctx context.Context, id string) (bool, error)
	Load(ctx context.Context, ID uuid.UUID) (*ResourceTypeScope, error)
	LookupForType(ctx context.Context, resourceTypeID uuid.UUID) ([]ResourceTypeScope, error)
	List(ctx context.Context, resourceType *resourcetype.ResourceType) ([]ResourceTypeScope, error)
	//ListByName(ctx context.Context, name string) ([]ResourceTypeScope, error)
	ListByResourceTypeAndScope(ctx context.Context, resourceTypeID uuid.UUID, scopeName string) ([]ResourceTypeScope, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormResourceTypeScopeRepository) TableName() string {
	return "resource_type_scope"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormResourceTypeScopeRepository) CheckExists(ctx context.Context, id string) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				resource_type_scope_id=$1
				AND deleted_at IS NULL
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, id).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), id)
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

// CRUD Functions

// Load returns a single ResourceTypeScope as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormResourceTypeScopeRepository) Load(ctx context.Context, id uuid.UUID) (*ResourceTypeScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "load"}, time.Now())
	var native ResourceTypeScope
	//err := m.db.Preload("ResourceType").Table(m.TableName()).Where("resource_type_scope_id = ?", id).Find(&native).Error
	err := m.db.Table(m.TableName()).Preload("ResourceType").Where("resource_type_scope_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("resource_type_scope", id.String())
	}
	return &native, errs.WithStack(err)
}

func (m *GormResourceTypeScopeRepository) LookupForType(ctx context.Context, resourceTypeID uuid.UUID) ([]ResourceTypeScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "load"}, time.Now())
	var native []ResourceTypeScope
	err := m.db.Table(m.TableName()).Preload("ResourceType").Where("resource_type_id = ?", resourceTypeID).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		// If there are no records found then return an empty slice of the correct type
		return []ResourceTypeScope{}, nil
	}
	return native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormResourceTypeScopeRepository) Create(ctx context.Context, u *ResourceTypeScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "create"}, time.Now())
	if u.ResourceTypeScopeID == uuid.Nil {
		u.ResourceTypeScopeID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": u.ResourceTypeScopeID,
			"err": err,
		}, "unable to create the resource type scope")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": u.ResourceTypeScopeID,
	}, "Resource Type Scope created!")
	return nil
}

// Save modifies a single record
func (m *GormResourceTypeScopeRepository) Save(ctx context.Context, model *ResourceTypeScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ResourceTypeScopeID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": model.ResourceTypeScopeID,
			"err": err,
		}, "unable to update resource type scope")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": model.ResourceTypeScopeID,
	}, "Resource Type Scope saved!")
	return nil
}

// Delete removes a single record.
func (m *GormResourceTypeScopeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "delete"}, time.Now())

	obj := ResourceTypeScope{ResourceTypeScopeID: id}

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type_scope_id": id,
			"err": err,
		}, "unable to delete the resource type scope")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_type_scope_id": id,
	}, "Resource type scope deleted!")

	return nil
}

// List return all resource type scopes
func (m *GormResourceTypeScopeRepository) List(ctx context.Context, resourceType *resourcetype.ResourceType) ([]ResourceTypeScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "list"}, time.Now())
	var rows []ResourceTypeScope

	var err error
	if resourceType != nil {
		err = m.db.Where("resource_type_id = ?", resourceType.ResourceTypeID).Order("name").Find(&rows).Error
	} else {
		err = m.db.Order("name").Find(&rows).Error
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

/*

// ListByName returns all resource type scopes filtered by name
func (m *GormResourceTypeScopeRepository) ListByName(ctx context.Context, name string) ([]ResourceTypeScope, error) {
	return m.Query(FilterByScopeName(name))
}
*/
// ListByResourceTypeAndScope returns all resource type scopes filtered by name and scope.
func (m *GormResourceTypeScopeRepository) ListByResourceTypeAndScope(ctx context.Context, resourceTypeID uuid.UUID, name string) ([]ResourceTypeScope, error) {
	return m.Query(FilterByScopeName(name), FilterByResourceTypeID(resourceTypeID))
}

// Query expose an open ended Query model
func (m *GormResourceTypeScopeRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ResourceTypeScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource_type_scope", "query"}, time.Now())
	var resourcetypeScopes []ResourceTypeScope
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&resourcetypeScopes).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"resource_type_scopes": resourcetypeScopes,
	}, "query executed successfully!")

	return resourcetypeScopes, nil
}

// FilterByScopeName is a gorm filter by 'name'
func FilterByScopeName(name string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("name = ?", name)
	}
}

// FilterByResourceTypeID is a gorm filter by 'name'
func FilterByResourceTypeID(id uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("resource_type_id = ?", id.String())
	}
}
