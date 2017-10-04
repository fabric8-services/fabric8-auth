package token

import (
	"context"
	"strconv"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"

	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// ExternalProvider describes a single ExternalProvider
type ExternalProvider struct {
	gormsupport.Lifecycle
	ID   uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
	Type string
	URL  string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ExternalProvider) TableName() string {
	return "external_providers"
}

// GetETagData returns the field values to use to generate the ETag
func (m ExternalProvider) GetETagData() []interface{} {
	// using the 'ID' and 'UpdatedAt' (converted to number of seconds since epoch) fields
	return []interface{}{m.ID, strconv.FormatInt(m.UpdatedAt.Unix(), 10)}
}

// GetLastModified returns the last modification time
func (m ExternalProvider) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormExternalProviderRepository is the implementation of the storage interface for
// ExternalProvider.
type GormExternalProviderRepository struct {
	db *gorm.DB
}

// NewExternalProviderRepository creates a new storage type.
func NewExternalProviderRepository(db *gorm.DB) *GormExternalProviderRepository {
	return &GormExternalProviderRepository{db: db}
}

// ExternalProviderRepository represents the storage interface.
type ExternalProviderRepository interface {
	repository.Exister
	Load(ctx context.Context, id uuid.UUID) (*ExternalProvider, error)
	Create(ctx context.Context, ExternalProvider *ExternalProvider) error
	Save(ctx context.Context, ExternalProvider *ExternalProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalProvider, error)
	IsValid(context.Context, uuid.UUID) bool
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormExternalProviderRepository) TableName() string {
	return "external_providers"
}

// Load returns a single ExternalProvider as a Database Model
func (m *GormExternalProviderRepository) Load(ctx context.Context, id uuid.UUID) (*ExternalProvider, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "load"}, time.Now())

	var native ExternalProvider
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("ExternalProvider", id.String()))
	}

	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormExternalProviderRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormExternalProviderRepository) Create(ctx context.Context, model *ExternalProvider) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "create"}, time.Now())
	if model.ID == uuid.Nil {
		model.ID = uuid.NewV4()
	}
	err := m.db.Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"ExternalProvider_id": model.ID,
			"err": err,
		}, "unable to create the ExternalProvider")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"ExternalProvider_id": model.ID,
	}, "ExternalProvider created!")
	return nil
}

// Save modifies a single record.
func (m *GormExternalProviderRepository) Save(ctx context.Context, model *ExternalProvider) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"ExternalProvider_id": model.ID,
			"ctx": ctx,
			"err": err,
		}, "unable to update the ExternalProvider")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error

	log.Debug(ctx, map[string]interface{}{
		"ExternalProvider_id": model.ID,
	}, "ExternalProvider saved!")

	return errs.WithStack(err)
}

// Delete removes a single record.
func (m *GormExternalProviderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "delete"}, time.Now())

	obj := ExternalProvider{ID: id}
	db := m.db.Delete(obj)

	if db.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"ExternalProvider_id": id,
			"err": db.Error,
		}, "unable to delete the ExternalProvider")
		return errs.WithStack(db.Error)
	}
	if db.RowsAffected == 0 {
		return errors.NewNotFoundError("ExternalProvider", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"ExternalProvider_id": id,
	}, "ExternalProvider deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormExternalProviderRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalProvider, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProvider", "query"}, time.Now())
	var externalProviders []ExternalProvider
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&externalProviders).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"ExternalProvider_query": externalProviders,
	}, "ExternalProvider query executed successfully!")

	return externalProviders, nil
}

// ExternalProviderFilterByURL is a gorm filter for a Belongs To relationship.
func ExternalProviderFilterByURL(url string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("url = ?", url).Limit(1)
	}
}

// ExternalProviderFilterByType is a gorm filter by 'Type'
func ExternalProviderFilterByType(Type string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("type = ?", Type)
	}
}

// IsValid returns true if the ExternalProvider exists
func (m *GormExternalProviderRepository) IsValid(ctx context.Context, id uuid.UUID) bool {
	_, err := m.Load(ctx, id)
	if err != nil {
		return false
	}
	return true
}
