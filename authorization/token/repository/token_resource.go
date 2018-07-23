package repository

import (
	"context"
	"time"

	"fmt"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type TokenResource struct {
	// This is the primary key value
	TokenID uuid.UUID `sql:"type:uuid" gorm:"primary_key;column:token_id"`

	ResourceID string `sql:"type:string" gorm:"primary_key;column:resource_id"`

	Scopes string

	Status int

	LastAccessed time.Time
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m TokenResource) TableName() string {
	return "token_resource"
}

// GormTokenResourceRepository is the implementation of the storage interface for Resource.
type GormTokenResourceRepository struct {
	db *gorm.DB
}

// NewTokenResourceRepository creates a new storage type.
func NewTokenResourceRepository(db *gorm.DB) TokenResourceRepository {
	return &GormTokenResourceRepository{db: db}
}

func (m *GormTokenResourceRepository) TableName() string {
	return "token_resource"
}

// TokenResourceRepository represents the storage interface.
type TokenResourceRepository interface {
	CheckExists(ctx context.Context, tokenID uuid.UUID, resourceID string) (bool, error)
	Load(ctx context.Context, tokenID uuid.UUID, resourceID string) (*TokenResource, error)
	Create(ctx context.Context, token *TokenResource) error
	Save(ctx context.Context, token *TokenResource) error
	Delete(ctx context.Context, tokenID uuid.UUID, resourceID string) error
	ListForToken(ctx context.Context, tokenID uuid.UUID) ([]TokenResource, error)
}

// CheckExists returns true if the given ID exists otherwise returns an error
func (m *GormTokenResourceRepository) CheckExists(ctx context.Context, tokenID uuid.UUID, resourceID string) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				token_id=$1
        AND resource_id=$2
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, tokenID, resourceID).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), fmt.Sprintf("%s:%s", tokenID.String(), resourceID))
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

// Load returns a single TokenResource as a Database Model
func (m *GormTokenResourceRepository) Load(ctx context.Context, tokenID uuid.UUID, resourceID string) (*TokenResource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "load"}, time.Now())

	var native TokenResource
	err := m.db.Table(m.TableName()).Where("token_id = ? AND resource_id = ?", tokenID, resourceID).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError(m.TableName(), fmt.Sprintf("%s:%s", tokenID.String(), resourceID)))
	}

	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormTokenResourceRepository) Create(ctx context.Context, tokenResource *TokenResource) error {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "create"}, time.Now())

	err := m.db.Create(tokenResource).Error
	if err != nil {
		if gormsupport.IsUniqueViolation(err, "token_resource_pkey") {
			return errors.NewDataConflictError(fmt.Sprintf("token resource with ID %s:%s already exists",
				tokenResource.TokenID, tokenResource.ResourceID))
		}

		log.Error(ctx, map[string]interface{}{
			"token_id":    tokenResource.TokenID,
			"resource_id": tokenResource.ResourceID,
			"err":         err,
		}, "unable to create the token resource")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"token_id":    tokenResource.TokenID,
		"resource_id": tokenResource.ResourceID,
	}, "Token resource created!")
	return nil
}

// Save modifies a single record.
func (m *GormTokenResourceRepository) Save(ctx context.Context, tokenResource *TokenResource) error {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "save"}, time.Now())

	obj, err := m.Load(ctx, tokenResource.TokenID, tokenResource.ResourceID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id":    tokenResource.TokenID,
			"resource_id": tokenResource.ResourceID,
			"err":         err,
		}, "unable to update token resource")
		return errs.WithStack(err)
	}

	err = m.db.Model(obj).Updates(tokenResource).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id":    tokenResource.TokenID,
			"resource_id": tokenResource.ResourceID,
			"err":         err,
		}, "unable to update the token resource")

		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"token_id":    tokenResource.TokenID,
		"resource_id": tokenResource.ResourceID,
	}, "Token resource saved!")

	return nil
}

// Delete removes a single record.
func (m *GormTokenResourceRepository) Delete(ctx context.Context, tokenID uuid.UUID, resourceID string) error {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "delete"}, time.Now())

	obj := TokenResource{TokenID: tokenID, ResourceID: resourceID}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id":    tokenID,
			"resource_id": resourceID,
			"err":         result.Error,
		}, "unable to delete the token resource")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("token_resource", fmt.Sprintf("%s:%s", tokenID.String(), resourceID))
	}

	log.Debug(ctx, map[string]interface{}{
		"token_id":    tokenID,
		"resource_id": resourceID,
	}, "Token resource deleted!")

	return nil
}

func (m *GormTokenResourceRepository) ListForToken(ctx context.Context, tokenID uuid.UUID) ([]TokenResource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "token_resource", "ListForToken"}, time.Now())
	var rows []TokenResource

	err := m.db.Model(&TokenResource{}).Where("token_id = ?", tokenID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}
