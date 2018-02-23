package repository

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormsupport"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	errs "github.com/pkg/errors"
)

type ResourceType struct {
	gormsupport.Lifecycle

	ResourceTypeID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:resource_type_id"`
	// The resource type name
	Name string
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
	Lookup(ctx context.Context, name string) (*ResourceType, error)
	List(ctx context.Context) ([]ResourceType, error)
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
		return nil, errors.NewNotFoundError("resource_type", name)
	}
	return &native, err
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
