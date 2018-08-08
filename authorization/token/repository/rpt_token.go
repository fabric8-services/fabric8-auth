package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type RPTToken struct {
	// This is the primary key value
	TokenID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:token_id"`

	// The timestamp when the token will expire
	ExpiryTime time.Time

	IdentityID uuid.UUID

	Status int
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m RPTToken) TableName() string {
	return "rpt_token"
}

func (m *RPTToken) Valid() bool {
	return m.Status == 0
}

// GormRPTTokenRepository is the implementation of the storage interface for RPTToken.
type GormRPTTokenRepository struct {
	db *gorm.DB
}

// NewRPTTokenRepository creates a new storage type.
func NewRPTTokenRepository(db *gorm.DB) RPTTokenRepository {
	return &GormRPTTokenRepository{db: db}
}

func (m *GormRPTTokenRepository) TableName() string {
	return "rpt_token"
}

// RPTTokenRepository represents the storage interface.
type RPTTokenRepository interface {
	CheckExists(ctx context.Context, id uuid.UUID) (bool, error)
	Load(ctx context.Context, id uuid.UUID) (*RPTToken, error)
	Create(ctx context.Context, token *RPTToken) error
	Save(ctx context.Context, token *RPTToken) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListForIdentity(ctx context.Context, id uuid.UUID) ([]RPTToken, error)
}

// CRUD Functions

// CheckExists returns true if the given ID exists otherwise returns an error
func (m *GormRPTTokenRepository) CheckExists(ctx context.Context, id uuid.UUID) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "rpt_token", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				token_id=$1
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, id).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), id.String())
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

// Load returns a single RPTToken as a Database Model
func (m *GormRPTTokenRepository) Load(ctx context.Context, id uuid.UUID) (*RPTToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "rpt_token", "load"}, time.Now())

	var native RPTToken
	err := m.db.Table(m.TableName()).Where("token_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("rpt_token", id.String()))
	}

	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormRPTTokenRepository) Create(ctx context.Context, token *RPTToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "rpt_token", "create"}, time.Now())

	// If no identifier has been specified for the new token, then generate one
	if token.TokenID == uuid.Nil {
		token.TokenID = uuid.NewV4()
	}

	// TODO read token expiry duration from configuration
	token.ExpiryTime = time.Now().Add(12 * time.Hour)

	err := m.db.Create(token).Error
	if err != nil {
		if gormsupport.IsUniqueViolation(err, "rpt_token_pkey") {
			return errors.NewDataConflictError(fmt.Sprintf("token with ID %s already exists", token.TokenID))
		}

		log.Error(ctx, map[string]interface{}{
			"token_id": token.TokenID,
			"err":      err,
		}, "unable to create the token")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"token_id": token.TokenID,
	}, "Token created!")
	return nil
}

// Save modifies a single record.
func (m *GormRPTTokenRepository) Save(ctx context.Context, token *RPTToken) error {
	defer goa.MeasureSince([]string{"goa", "db", "rpt_token", "save"}, time.Now())

	obj, err := m.Load(ctx, token.TokenID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id": token.TokenID,
			"err":      err,
		}, "unable to update token")
		return errs.WithStack(err)
	}

	err = m.db.Model(obj).Updates(token).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id": token.TokenID,
			"err":      err,
		}, "unable to update the token")

		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"token_id": token.TokenID,
	}, "Token saved!")

	return nil
}

// Delete removes a single record.
func (m *GormRPTTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "token", "delete"}, time.Now())

	obj := RPTToken{TokenID: id}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"token_id": id,
			"err":      result.Error,
		}, "unable to delete the token")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("rpt_token", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"token_id": id,
	}, "Token deleted!")

	return nil
}

func (m *GormRPTTokenRepository) ListForIdentity(ctx context.Context, identityID uuid.UUID) ([]RPTToken, error) {
	defer goa.MeasureSince([]string{"goa", "db", "token", "ListForIdentity"}, time.Now())
	var rows []RPTToken

	err := m.db.Model(&RPTToken{}).Where("identity_id = ?", identityID).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}
