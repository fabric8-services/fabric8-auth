package repository

import (
	"context"
	"time"

	repository "github.com/fabric8-services/fabric8-auth/application/repository/base"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type VerificationCode struct {
	gormsupport.Lifecycle
	ID     uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
	User   User
	UserID uuid.UUID `sql:"type:uuid"`

	Code string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m VerificationCode) TableName() string {
	return "verification_codes"
}

// GormVerificationCodeRepository is the implementation of the storage interface for
// VerificationCode.
type GormVerificationCodeRepository struct {
	db *gorm.DB
}

// NewVerificationCodeRepository creates a new storage type.
func NewVerificationCodeRepository(db *gorm.DB) *GormVerificationCodeRepository {
	return &GormVerificationCodeRepository{db: db}
}

// VerificationCodeRepository represents the storage interface.
type VerificationCodeRepository interface {
	repository.Exister
	Load(ctx context.Context, id uuid.UUID) (*VerificationCode, error)
	LoadByCode(ctx context.Context, code string) ([]VerificationCode, error)
	Create(ctx context.Context, VerificationCode *VerificationCode) error
	Save(ctx context.Context, VerificationCode *VerificationCode) error
	Delete(ctx context.Context, id uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]VerificationCode, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormVerificationCodeRepository) TableName() string {
	return "verification_codes"
}

// CRUD Functions

// Load returns a single VerificationCode as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormVerificationCodeRepository) Load(ctx context.Context, id uuid.UUID) (*VerificationCode, error) {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "load"}, time.Now())

	var native VerificationCode
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("verification_code_id", id.String())
	}

	return &native, errs.WithStack(err)
}

// LoadByCode loads result by filtering with respect to the verificate code.
func (m *GormVerificationCodeRepository) LoadByCode(ctx context.Context, code string) ([]VerificationCode, error) {
	return m.Query(VerificationCodeWithUser(), VerificationCodeFilterByCode(code)) // maybe load with user?
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormVerificationCodeRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormVerificationCodeRepository) Create(ctx context.Context, model *VerificationCode) error {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "create"}, time.Now())
	if model.ID == uuid.Nil {
		model.ID = uuid.NewV4()
	}
	err := m.db.Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"verification_code_id": model.ID,
			"err":                  err,
		}, "unable to create the verification_code")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"verification_code_id": model.ID,
	}, "verification_code created!")
	return nil
}

// Save modifies a single record.
func (m *GormVerificationCodeRepository) Save(ctx context.Context, model *VerificationCode) error {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"verification_code_id": model.ID,
			"err":                  err,
		}, "unable to update the verification_code")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error

	log.Debug(ctx, map[string]interface{}{
		"verification_code_id": model.ID,
	}, "verification_code saved!")

	return errs.WithStack(err)
}

// Delete removes a single record. This is a hard delete!
func (m *GormVerificationCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "delete"}, time.Now())

	obj := VerificationCode{ID: id}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"verification_code_id": id,
			"err":                  result.Error,
		}, "unable to delete the verification_code")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("verification_code", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"verification_code_id": id,
	}, "verification_code deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormVerificationCodeRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]VerificationCode, error) {
	defer goa.MeasureSince([]string{"goa", "db", "VerificationCode", "query"}, time.Now())
	var verificationCodes []VerificationCode
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&verificationCodes).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"verification_code_query": verificationCodes,
	}, "verification_code query executed successfully!")

	return verificationCodes, nil
}

// VerificationCodeFilterByUserID is a gorm filter for a Belongs To relationship.
func VerificationCodeFilterByUserID(userID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("user_id = ?", userID)
	}
}

// VerificationCodeFilterByCode is a gorm filter for a Belongs To relationship.
func VerificationCodeFilterByCode(code string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("code = ?", code)
	}
}

// VerificationCodeWithUser is a gorm filter for preloading the user relationship.
func VerificationCodeWithUser() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Preload("User")
	}
}
