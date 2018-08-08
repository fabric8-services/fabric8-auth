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

type PrivilegeCache struct {
	gormsupport.Lifecycle

	// This is the primary key value
	PrivilegeCacheID uuid.UUID `sql:"type:uuid" gorm:"primary_key;column:privilege_cache_id"`

	IdentityID uuid.UUID `sql:"type:uuid" gorm:"column:identity_id"`

	ResourceID string `sql:"type:string" gorm:"column:resource_id"`

	Scopes string

	Stale bool `sql:"type:boolean"`

	ExpiryTime time.Time
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m PrivilegeCache) TableName() string {
	return "privilege_cache"
}

// GormPrivilegeCacheRepository is the implementation of the storage interface for Resource.
type GormPrivilegeCacheRepository struct {
	db *gorm.DB
}

// NewPrivilegeCacheRepository creates a new storage type.
func NewPrivilegeCacheRepository(db *gorm.DB) PrivilegeCacheRepository {
	return &GormPrivilegeCacheRepository{db: db}
}

func (m *GormPrivilegeCacheRepository) TableName() string {
	return "privilege_cache"
}

// PrivilegeCacheRepository represents the storage interface.
type PrivilegeCacheRepository interface {
	CheckExists(ctx context.Context, privilegeCacheID uuid.UUID) (bool, error)
	Load(ctx context.Context, privilegeCacheID uuid.UUID) (*PrivilegeCache, error)
	Create(ctx context.Context, cache *PrivilegeCache) error
	Save(ctx context.Context, cache *PrivilegeCache) error
	Delete(ctx context.Context, privilegeCacheID uuid.UUID) error
	ListForToken(ctx context.Context, tokenID uuid.UUID) ([]PrivilegeCache, error)
}

// CheckExists returns true if the given ID exists otherwise returns an error
func (m *GormPrivilegeCacheRepository) CheckExists(ctx context.Context, privilegeCacheID uuid.UUID) (bool, error) {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "exists"}, time.Now())

	var exists bool
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %[1]s
			WHERE
				privilege_cache_id=$1
		)`, m.TableName())

	err := m.db.CommonDB().QueryRow(query, privilegeCacheID).Scan(&exists)
	if err == nil && !exists {
		return exists, errors.NewNotFoundError(m.TableName(), fmt.Sprintf("%s", privilegeCacheID.String()))
	}
	if err != nil {
		return false, errors.NewInternalError(ctx, errs.Wrapf(err, "unable to verify if %s exists", m.TableName()))
	}
	return exists, nil
}

// Load returns a single PrivilegeCache as a Database Model
func (m *GormPrivilegeCacheRepository) Load(ctx context.Context, privilegeCacheID uuid.UUID) (*PrivilegeCache, error) {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "load"}, time.Now())

	var native PrivilegeCache
	err := m.db.Table(m.TableName()).Where("privilege_cache_id = ?", privilegeCacheID).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError(m.TableName(), fmt.Sprintf("%s", privilegeCacheID.String())))
	}

	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormPrivilegeCacheRepository) Create(ctx context.Context, privilegeCache *PrivilegeCache) error {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "create"}, time.Now())

	if privilegeCache.PrivilegeCacheID == uuid.Nil {
		privilegeCache.PrivilegeCacheID = uuid.NewV4()
	}

	err := m.db.Create(privilegeCache).Error
	if err != nil {
		if gormsupport.IsUniqueViolation(err, "privilege_cache_pkey") {
			return errors.NewDataConflictError(fmt.Sprintf("privilege cache with ID %s already exists",
				privilegeCache.PrivilegeCacheID))
		}

		log.Error(ctx, map[string]interface{}{
			"privilege_cache_id":    privilegeCache.PrivilegeCacheID,
			"err":         err,
		}, "unable to create the privilege cache")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"privilege_cache_id":    privilegeCache.PrivilegeCacheID,
	}, "Privilege cache created!")
	return nil
}

// Save modifies a single record.
func (m *GormPrivilegeCacheRepository) Save(ctx context.Context, privilegeCache *PrivilegeCache) error {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "save"}, time.Now())

	obj, err := m.Load(ctx, privilegeCache.PrivilegeCacheID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"privilege_cache_id":    privilegeCache.PrivilegeCacheID,
			"err":         err,
		}, "unable to update privilege cache")
		return errs.WithStack(err)
	}

	err = m.db.Model(obj).Updates(privilegeCache).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"privilege_cache_id":    privilegeCache.PrivilegeCacheID,
			"err":         err,
		}, "unable to update the privilege cache")

		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"privilege_cache_id":    privilegeCache.PrivilegeCacheID,
	}, "Privilege cache saved!")

	return nil
}

// Delete removes a single record.
func (m *GormPrivilegeCacheRepository) Delete(ctx context.Context, privilegeCacheID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "delete"}, time.Now())

	obj := PrivilegeCache{PrivilegeCacheID: privilegeCacheID}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"privilege_cache_id":    privilegeCacheID,
			"err":         result.Error,
		}, "unable to delete the privilege cache")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("privilege_cache", fmt.Sprintf("%s", privilegeCacheID.String()))
	}

	log.Debug(ctx, map[string]interface{}{
		"privilege_cache_id":    privilegeCacheID,
	}, "Privilege cache deleted!")

	return nil
}

func (m *GormPrivilegeCacheRepository) ListForToken(ctx context.Context, tokenID uuid.UUID) ([]PrivilegeCache, error) {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "ListForToken"}, time.Now())
	var rows []PrivilegeCache

	err := m.db.Table(m.TableName()).Where("deleted_at IS NULL AND privilege_cache_id IN (SELECT tp.privilege_cache_id FROM token_privilege tp WHERE tp.token_id = ?)",
		tokenID).Scan(&rows).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}
