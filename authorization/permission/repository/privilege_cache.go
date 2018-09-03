package repository

import (
	"context"
	"time"

	"fmt"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"strings"
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

// Returns the scopes as a string array.  If scopes is empty, returns an empty array
func (m PrivilegeCache) ScopesAsArray() []string {
	if strings.TrimSpace(m.Scopes) == "" {
		return []string{}
	} else {
		return strings.Split(m.Scopes, ",")
	}
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
	FindForIdentityResource(ctx context.Context, identityID uuid.UUID, resourceID string) (*PrivilegeCache, error)
	FlagAsStale(ctx context.Context, identityID uuid.UUID, resourceID string) error
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
			"privilege_cache_id": privilegeCache.PrivilegeCacheID,
			"err":                err,
		}, "unable to create the privilege cache")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"privilege_cache_id": privilegeCache.PrivilegeCacheID,
	}, "Privilege cache created!")
	return nil
}

// Save modifies a single record.
func (m *GormPrivilegeCacheRepository) Save(ctx context.Context, privilegeCache *PrivilegeCache) error {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "save"}, time.Now())

	err := m.db.Save(privilegeCache).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"privilege_cache_id": privilegeCache.PrivilegeCacheID,
			"err":                err,
		}, "unable to update the privilege cache")

		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"privilege_cache_id": privilegeCache.PrivilegeCacheID,
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
			"privilege_cache_id": privilegeCacheID,
			"err":                result.Error,
		}, "unable to delete the privilege cache")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("privilege_cache", fmt.Sprintf("%s", privilegeCacheID.String()))
	}

	log.Debug(ctx, map[string]interface{}{
		"privilege_cache_id": privilegeCacheID,
	}, "Privilege cache deleted!")

	return nil
}

func (m *GormPrivilegeCacheRepository) FindForIdentityResource(ctx context.Context, identityID uuid.UUID, resourceID string) (*PrivilegeCache, error) {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "FindForIdentityResource"}, time.Now())

	var native PrivilegeCache
	err := m.db.Table(m.TableName()).Where("identity_id = ? AND resource_id = ?", identityID, resourceID).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError(m.TableName(), fmt.Sprintf("identity_id:%s,resource_id:%s", identityID.String(), resourceID))
	}

	return &native, errs.WithStack(err)
}

// FlagAsStale executes two update queries; the first sets the stale flag to true for all privilege cache records where
// the identity ID is equal to, or a descendent of (via memberships) the specified identity ID, and the resourceID is
// equal to, or a descendent of (via the resource hierarchy) the specified resource ID.
// The second query updates the token table, setting the STALE flag of the token STATUS field to true, for all
// token records that are mapped to the corresponding privilege cache records in the first query, via the
// many-to-many TOKEN_PRIVILEGE table
func (m *GormPrivilegeCacheRepository) FlagAsStale(ctx context.Context, identityID uuid.UUID, resourceID string) error {
	defer goa.MeasureSince([]string{"goa", "db", "privilege_cache", "FlagAsStale"}, time.Now())

	result := m.db.Exec(`WITH identity_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    member_id
	  FROM
	    membership
	  WHERE
	    member_of = ? /* IDENTITY_ID */
	  UNION SELECT
	    p.member_id
	  FROM
	    membership p INNER JOIN m ON m.member_id = p.member_of
	  )
	  SELECT
	    member_id AS identity_id
	  FROM 
	    m
	  UNION SELECT
	    id
	  FROM
	    identities
	  WHERE
	    id = ? /* IDENTITY_ID */
), 
resource_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    resource_id, parent_resource_id
	  FROM
	    resource
	  WHERE
	    resource_id = ? /* RESOURCE_ID */
	  UNION SELECT
	    p.resource_id, p.parent_resource_id
	  FROM
	    resource p INNER JOIN m ON m.resource_id = p.parent_resource_id
	  )
	  SELECT
	    m.resource_id
	  FROM
	    m
)
UPDATE privilege_cache SET
  STALE = true
WHERE
  resource_id IN (SELECT resource_id FROM resource_hierarchy)
  AND identity_id IN (SELECT identity_id FROM identity_hierarchy)
  AND deleted_at IS NULL
  `, identityID, identityID, resourceID)

	if result.Error != nil {
		return errors.NewInternalError(ctx, result.Error)
	}

	result = m.db.Exec(`WITH identity_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    member_id
	  FROM
	    membership
	  WHERE
	    member_of = ? /* IDENTITY_ID */
	  UNION SELECT
	    p.member_id
	  FROM
	    membership p INNER JOIN m ON m.member_id = p.member_of
	  )
	  SELECT
	    member_id AS identity_id
	  FROM 
	    m
	  UNION SELECT
	    id
	  FROM
	    identities
	  WHERE
	    id = ? /* IDENTITY_ID */
), 
resource_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    resource_id, parent_resource_id
	  FROM
	    resource
	  WHERE
	    resource_id = ? /* RESOURCE_ID */
	  UNION SELECT
	    p.resource_id, p.parent_resource_id
	  FROM
	    resource p INNER JOIN m ON m.resource_id = p.parent_resource_id
	  )
	  SELECT
	    m.resource_id
	  FROM
	    m
)
UPDATE token t SET
  STATUS = STATUS | ? /* TOKEN_STATUS_STALE */
FROM
  token_privilege tp,
  privilege_cache pc
WHERE
  t.token_id = tp.token_id
  AND tp.privilege_cache_id = pc.privilege_cache_id
  AND pc.resource_id IN (SELECT resource_id FROM resource_hierarchy)
  AND pc.identity_id IN (SELECT identity_id FROM identity_hierarchy)
  AND pc.deleted_at IS NULL
`, identityID, identityID, resourceID, token.TOKEN_STATUS_STALE)

	if result.Error != nil {
		return errors.NewInternalError(ctx, result.Error)
	}

	log.Debug(ctx, map[string]interface{}{
		"rows_marked_stale": result.RowsAffected,
	}, "Privilege cache rows marked stale")

	return nil
}
