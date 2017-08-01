package provider

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// ExternalProviderToken describes a single ExternalProviderToken
type ExternalProviderToken struct {
	gormsupport.Lifecycle
	ID           uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
	IdentityID   uuid.UUID `sql:"type:uuid"`
	Token        string
	ProviderType string
	Version      int
}

// GetETagData returns the field values to use to generate the ETag
func (m ExternalProviderToken) GetETagData() []interface{} {
	return []interface{}{m.ID, m.Version}
}

// GetLastModified returns the Extelast modification time
func (m ExternalProviderToken) GetLastModified() time.Time {
	return m.UpdatedAt.Truncate(time.Second)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m ExternalProviderToken) TableName() string {
	return "external_provider_tokens"
}

// ExternalProviderTokenRepository describes interactions with ExternalProviderTokens
type ExternalProviderTokenRepository interface {
	repository.Exister
	Create(ctx context.Context, u *ExternalProviderToken) error
	Load(ctx context.Context, identityID uuid.UUID, providerType string) (*ExternalProviderToken, error)
}

// NewExternalProviderTokenRepository creates a new storage type.
func NewExternalProviderTokenRepository(db *gorm.DB) ExternalProviderTokenRepository {
	return &GormExternalProviderTokenRepository{db: db}
}

// GormExternalProviderTokenRepository is the implementation of the storage interface for ExternalProviderTokens.
type GormExternalProviderTokenRepository struct {
	db *gorm.DB
}

// Create creates a new record.
func (m *GormExternalProviderTokenRepository) Create(ctx context.Context, u *ExternalProviderToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "externalProviderToken", "create"}, time.Now())
	u.ID = uuid.NewV4()
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "error adding ExternalProviderToken: %s", err.Error())
		return err
	}
	return nil
}

// Load ExternalProviderToken related to identity & provider_type
func (m *GormExternalProviderTokenRepository) Load(ctx context.Context, identityID uuid.UUID, providerType string) (*ExternalProviderToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "ExternalProviderToken", "query"}, time.Now())
	var obj ExternalProviderToken
	err := m.db.Where("identity_id = ?", identityID).Where("provider_type = ?", providerType).First(&obj).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return &obj, nil
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormExternalProviderTokenRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "externalProviderToken", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, ExternalProviderToken{}.TableName(), id)
}
