package provider

import (
	"context"
	"strconv"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	repository "github.com/fabric8-services/fabric8-auth/application/repository/base"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// ExternalToken describes a single ExternalToken
type ExternalToken struct {
	gormsupport.LifecycleHardDelete
	ID         uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
	ProviderID uuid.UUID
	Token      string
	Scope      string
	Username   string
	IdentityID uuid.UUID `sql:"type:uuid"` // use NullUUID ?
	Identity   account.Identity
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ExternalToken) TableName() string {
	return "external_tokens"
}

// GetETagData returns the field values to use to generate the ETag
func (m ExternalToken) GetETagData() []interface{} {
	// using the 'ID' and 'UpdatedAt' (converted to number of seconds since epoch) fields
	return []interface{}{m.ID, strconv.FormatInt(m.UpdatedAt.Unix(), 10)}
}

// GetLastModified returns the last modification time
func (m ExternalToken) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormExternalTokenRepository is the implementation of the storage interface for
// ExternalToken.
type GormExternalTokenRepository struct {
	db *gorm.DB
}

// NewExternalTokenRepository creates a new storage type.
func NewExternalTokenRepository(db *gorm.DB) *GormExternalTokenRepository {
	return &GormExternalTokenRepository{db: db}
}

// ExternalTokenRepository represents the storage interface.
type ExternalTokenRepository interface {
	repository.Exister
	Load(ctx context.Context, id uuid.UUID) (*ExternalToken, error)
	Create(ctx context.Context, ExternalToken *ExternalToken) error
	Save(ctx context.Context, ExternalToken *ExternalToken) error
	Delete(ctx context.Context, id uuid.UUID) error
	LoadByProviderIDAndIdentityID(ctx context.Context, providerID uuid.UUID, identityID uuid.UUID) ([]ExternalToken, error)
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalToken, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormExternalTokenRepository) TableName() string {
	return "external_tokens"
}

// CRUD Functions

// Load returns a single ExternalToken as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormExternalTokenRepository) Load(ctx context.Context, id uuid.UUID) (*ExternalToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "load"}, time.Now())

	var native ExternalToken
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("external_token", id.String())
	}

	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormExternalTokenRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "exists"}, time.Now())
	return repository.CheckHardDeletableExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormExternalTokenRepository) Create(ctx context.Context, model *ExternalToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "create"}, time.Now())
	if model.ID == uuid.Nil {
		model.ID = uuid.NewV4()
	}
	err := m.db.Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"external_token_id": model.ID,
			"err":               err,
		}, "unable to create the external_token")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"external_token_id": model.ID,
	}, "external_token created!")
	return nil
}

// Save modifies a single record.
func (m *GormExternalTokenRepository) Save(ctx context.Context, model *ExternalToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"external_token_id": model.ID,
			"ctx":               ctx,
			"err":               err,
		}, "unable to update the external_token")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error

	log.Debug(ctx, map[string]interface{}{
		"external_token_id": model.ID,
	}, "external_token saved!")

	return errs.WithStack(err)
}

// Delete removes a single record. This is a hard delete!
func (m *GormExternalTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "delete"}, time.Now())

	obj := ExternalToken{ID: id}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"external_token_id": id,
			"err":               result.Error,
		}, "unable to delete the external_token")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("external_token", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"external_token_id": id,
	}, "external_token deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormExternalTokenRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]ExternalToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "query"}, time.Now())
	var externalProviderTokens []ExternalToken
	// if a query is returning multiple tokens, always return the latest token first
	err := m.db.Scopes(funcs...).Table(m.TableName()).Order("created_at desc").Find(&externalProviderTokens).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"external_provider_token_query": externalProviderTokens,
	}, "external_token query executed successfully!")

	return externalProviderTokens, nil
}

// LoadByProviderIDAndIdentityID loads tokens by IdentityID and ProviderID
func (m *GormExternalTokenRepository) LoadByProviderIDAndIdentityID(ctx context.Context, providerID uuid.UUID, identityID uuid.UUID) ([]ExternalToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalToken", "LoadByProviderIDAndIdentityID"}, time.Now())
	var externalProviderTokens []ExternalToken
	externalProviderTokens, err := m.Query(ExternalTokenFilterByIdentityID(identityID), ExternalTokenFilterByProviderID(providerID), ExternalTokenWithIdentity())
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return externalProviderTokens, nil
}

// ExternalTokenFilterByIdentityID is a gorm filter for a Belongs To relationship.
func ExternalTokenFilterByIdentityID(identityID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("identity_id = ?", identityID)
	}
}

// ExternalTokenFilterByProviderID is a gorm filter by 'external_provider_type'
func ExternalTokenFilterByProviderID(providerID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("provider_id = ?", providerID)
	}
}

// ExternalTokenWithIdentity is a gorm filter for preloading the identity relationship.
func ExternalTokenWithIdentity() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Preload("Identity")
	}
}
