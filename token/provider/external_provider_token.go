package provider

import (
	"context"
	"strconv"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// ExternalProviderToken describes a single ExternalProviderToken
type ExternalProviderToken struct {
	gormsupport.Lifecycle
	ID                   uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
	ExternalProviderType string
	Token                string
	Scope                string
	IdentityID           uuid.UUID `sql:"type:uuid"` // use NullUUID ?
	Identity             account.Identity
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ExternalProviderToken) TableName() string {
	return "external_provider_tokens"
}

// GetETagData returns the field values to use to generate the ETag
func (m ExternalProviderToken) GetETagData() []interface{} {
	// using the 'ID' and 'UpdatedAt' (converted to number of seconds since epoch) fields
	return []interface{}{m.ID, strconv.FormatInt(m.UpdatedAt.Unix(), 10)}
}

// GetLastModified returns the last modification time
func (m ExternalProviderToken) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormExternalProviderTokenRepository is the implementation of the storage interface for
// ExternalProviderToken.
type GormExternalProviderTokenRepository struct {
	db *gorm.DB
}

// NewExternalProviderTokenRepository creates a new storage type.
func NewExternalProviderTokenRepository(db *gorm.DB) *GormExternalProviderTokenRepository {
	return &GormExternalProviderTokenRepository{db: db}
}

// ExternalProviderTokenRepository represents the storage interface.
type ExternalProviderTokenRepository interface {
	repository.Exister
	Load(ctx context.Context, id uuid.UUID) (*ExternalProviderToken, error)
	Create(ctx context.Context, ExternalProviderToken *ExternalProviderToken) error
	Save(ctx context.Context, ExternalProviderToken *ExternalProviderToken) error
	Delete(ctx context.Context, id uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalProviderToken, error)
	IsValid(context.Context, uuid.UUID) bool
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormExternalProviderTokenRepository) TableName() string {
	return "external_provider_tokens"

}

// CRUD Functions

// Load returns a single ExternalProviderToken as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormExternalProviderTokenRepository) Load(ctx context.Context, id uuid.UUID) (*ExternalProviderToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "load"}, time.Now())

	var native ExternalProviderToken
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("external_provider_token", id.String()))
	}

	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormExternalProviderTokenRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormExternalProviderTokenRepository) Create(ctx context.Context, model *ExternalProviderToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "create"}, time.Now())
	if model.ID == uuid.Nil {
		model.ID = uuid.NewV4()
	}
	err := m.db.Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"external_provider_token_id": model.ID,
			"err": err,
		}, "unable to create the external_provider_token")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"external_provider_token_id": model.ID,
	}, "external_provider_token created!")
	return nil
}

// Save modifies a single record.
func (m *GormExternalProviderTokenRepository) Save(ctx context.Context, model *ExternalProviderToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"external_provider_token_id": model.ID,
			"ctx": ctx,
			"err": err,
		}, "unable to update the external_provider_token")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error

	log.Debug(ctx, map[string]interface{}{
		"external_provider_token_id": model.ID,
	}, "external_provider_token saved!")

	return errs.WithStack(err)
}

// Delete removes a single record.
func (m *GormExternalProviderTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "delete"}, time.Now())

	obj := ExternalProviderToken{ID: id}
	db := m.db.Delete(obj)

	if db.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"external_provider_token_id": id,
			"err": db.Error,
		}, "unable to delete the external_provider_token")
		return errs.WithStack(db.Error)
	}
	if db.RowsAffected == 0 {
		return errors.NewNotFoundError("external_provider_token", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"external_provider_token_id": id,
	}, "external_provider_token deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormExternalProviderTokenRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalProviderToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "query"}, time.Now())
	var externalProviderTokens []ExternalProviderToken
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&externalProviderTokens).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"external_provider_token_query": externalProviderTokens,
	}, "external_provider_token query executed successfully!")

	return externalProviderTokens, nil
}

// ExternalProviderTokenFilterByIdentityID is a gorm filter for a Belongs To relationship.
func ExternalProviderTokenFilterByIdentityID(identityID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("identity_id = ?", identityID)
	}
}

// ExternalProviderTokenFilterByExternalProviderType is a gorm filter by 'external_provider_type'
func ExternalProviderTokenFilterByExternalProviderType(externalProviderType string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("external_provider_type = ?", externalProviderType)
	}
}

// ExternalProviderTokenWithIdentity is a gorm filter for preloading the identity relationship.
func ExternalProviderTokenWithIdentity() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Preload("Identity")
	}
}

// IsValid returns true if the ExternalProviderToken exists
func (m *GormExternalProviderTokenRepository) IsValid(ctx context.Context, id uuid.UUID) bool {
	_, err := m.Load(ctx, id)
	if err != nil {
		return false
	}
	return true
}
