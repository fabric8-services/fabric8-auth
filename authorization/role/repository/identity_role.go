package repository

import (
	"context"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	applicationrepo "github.com/fabric8-services/fabric8-auth/application/repository/base"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type IdentityRole struct {
	gormsupport.Lifecycle

	// This is the primary key value
	IdentityRoleID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:identity_role_id"`
	// The identity to which the role is assigned
	IdentityID uuid.UUID        `gorm:"type:uuid"`
	Identity   account.Identity `gorm:"foreignkey:IdentityID;association_foreignkey:ID"`
	// The resource to which the role is applied
	ResourceID string
	Resource   resource.Resource `gorm:"foreignkey:ResourceID;association_foreignkey:ResourceID"`
	// The role that is assigned
	RoleID uuid.UUID `gorm:"type:uuid"`
	Role   Role      `gorm:"foreignkey:RoleID;association_foreignkey:RoleID"`
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m IdentityRole) TableName() string {
	return "identity_role"
}

// GetLastModified returns the last modification time
func (m IdentityRole) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormIdentityRoleRepository is the implementation of the storage interface for IdentityRole.
type GormIdentityRoleRepository struct {
	db *gorm.DB
}

// NewIdentityRoleRepository creates a new storage type.
func NewIdentityRoleRepository(db *gorm.DB) IdentityRoleRepository {
	return &GormIdentityRoleRepository{db: db}
}

// IdentityRoleRepository represents the storage interface.
type IdentityRoleRepository interface {
	applicationrepo.Exister
	Load(ctx context.Context, ID uuid.UUID) (*IdentityRole, error)
	Create(ctx context.Context, u *IdentityRole) error
	Save(ctx context.Context, u *IdentityRole) error
	List(ctx context.Context) ([]IdentityRole, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	FindPermissions(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) ([]IdentityRole, error)
	FindIdentityRolesForIdentity(ctx context.Context, identityID uuid.UUID, resourceType *string) ([]authorization.IdentityAssociation, error)
	FindIdentityRolesByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]IdentityRole, error)
	FindIdentityRolesByResource(ctx context.Context, resourceID string) ([]IdentityRole, error)
	FindIdentityRolesByIdentityAndResource(ctx context.Context, resourceID string, identityID uuid.UUID) ([]IdentityRole, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormIdentityRoleRepository) TableName() string {
	return "identity_role"
}

// CRUD Functions

// Load returns a single IdentityRole as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormIdentityRoleRepository) Load(ctx context.Context, id uuid.UUID) (*IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "load"}, time.Now())
	var native IdentityRole
	err := m.db.Table(m.TableName()).Where("identity_role_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("identity_role", id.String())
	}
	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormIdentityRoleRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "exists"}, time.Now())
	var native IdentityRole
	err := m.db.Table(m.TableName()).Where("identity_role_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return errors.NewNotFoundError("identity_role", id)
	}
	return nil
}

// Create creates a new record.
func (m *GormIdentityRoleRepository) Create(ctx context.Context, u *IdentityRole) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "create"}, time.Now())
	if u.IdentityRoleID == uuid.Nil {
		u.IdentityRoleID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_role_id": u.IdentityRoleID,
			"err":              err,
		}, "unable to create the identity role")
		if gormsupport.IsUniqueViolation(err, "uq_identity_role_identity_role_resource") {
			return errs.WithStack(errors.NewDataConflictError(err.Error()))
		}
		if gormsupport.IsForeignKeyViolation(err, "identity_role_identity_id_fkey") {
			return errs.WithStack(errors.NewNotFoundError("identity", u.IdentityID.String()))
		}
		if gormsupport.IsForeignKeyViolation(err, "identity_role_resource_id_fkey") {
			return errs.WithStack(errors.NewNotFoundError("resource", u.ResourceID))
		}
		if gormsupport.IsForeignKeyViolation(err, "identity_role_role_id_fkey") {
			return errs.WithStack(errors.NewNotFoundError("role", u.RoleID.String()))
		}
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"identity_role_id": u.IdentityRoleID,
	}, "Identity Role created!")
	return nil
}

// Save modifies a single record
func (m *GormIdentityRoleRepository) Save(ctx context.Context, model *IdentityRole) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "save"}, time.Now())

	obj, err := m.Load(ctx, model.IdentityRoleID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_role_id": model.IdentityRoleID,
			"err":              err,
		}, "unable to update identity role")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_role_id": model.IdentityRoleID,
	}, "Identity Role saved!")
	return nil
}

// Delete removes a single record.
func (m *GormIdentityRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "delete"}, time.Now())

	obj := IdentityRole{IdentityRoleID: id}

	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_role_id": id,
			"err":              result.Error,
		}, "unable to delete the identity role")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("identity_role", id.String())
	}
	log.Debug(ctx, map[string]interface{}{
		"identity_role_id": id,
	}, "Identity role deleted!")

	return nil
}

// List returns all identity roles
func (m *GormIdentityRoleRepository) List(ctx context.Context) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var rows []IdentityRole

	err := m.db.Model(&resourcetype.ResourceType{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// FindPermissions returns an IdentityRole array containing entries that match the specified identity, resource and scope
func (m *GormIdentityRoleRepository) FindPermissions(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) ([]IdentityRole, error) {
	var results []IdentityRole
	err := m.db.Table(m.TableName()).Where(`deleted_at IS NULL AND identity_id IN (
  SELECT
    id
  FROM
    identities i
  WHERE
    id = ? /* IDENTITY_ID */
    OR id IN (
    WITH RECURSIVE m AS (
      SELECT 
        member_of 
      FROM 
        membership 
      WHERE 
        member_id = ? /* IDENTITY_ID */
      UNION SELECT 
        p.member_of 
      FROM 
        membership p INNER JOIN m ON m.member_of = p.member_id
    ) 
    SELECT member_of FROM m
    )
  )
  AND resource_id IN (
  WITH RECURSIVE m AS (
  SELECT
    resource_id, parent_resource_id
  FROM
    resource
  WHERE
    deleted_at IS NULL
    AND resource_id = ? /* RESOURCE_ID */
  UNION SELECT
    p.resource_id, p.parent_resource_id
  FROM
    resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
  )
  SELECT
    m.resource_id
  FROM
    m
  )
  AND (role_id IN (
    SELECT
      r.role_id
    FROM
      resource res,
      role r,
      role_scope rs,
      resource_type_scope rts
    WHERE
      res.resource_id = ? /* RESOURCE_ID */
      AND res.deleted_at IS NULL
      AND res.resource_type_id = r.resource_type_id
      AND r.deleted_at IS NULL
      AND r.role_id = rs.role_id
      AND rs.scope_id = rts.resource_type_scope_id
      AND rs.deleted_at IS NULL
      AND rts.name = ? /* SCOPE */
      AND rts.deleted_at IS NULL
  ) OR role_id IN (
    SELECT DISTINCT
      rl.role_id
    FROM
      (
    WITH RECURSIVE prm AS (
    SELECT
      rm.from_role_id,
      rm.to_role_id
    FROM
      role_mapping rm,
      role r,
      role_scope rs,
      resource_type_scope rts
    WHERE
      rm.deleted_at IS NULL
      AND rm.to_role_id = r.role_id
      AND r.deleted_at IS NULL
      AND r.role_id = rs.role_id
      AND rs.deleted_at IS NULL
      AND rs.scope_id = rts.resource_type_scope_id
      AND rts.deleted_at IS NULL
      AND rts.name = ? /* SCOPE */
      AND rm.resource_id IN (WITH RECURSIVE m AS ( /* only resources that are in the ancestor hierarchy */
      SELECT
        resource_id, parent_resource_id
      FROM
        resource
      WHERE
        resource_id = ? /* RESOURCE_ID */
        AND deleted_at IS NULL
      UNION SELECT
        p.resource_id, p.parent_resource_id
      FROM
        resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
      )
      SELECT
        m.resource_id
      FROM
        m)
    UNION SELECT
     trm.from_role_id,
     trm.to_role_id
    FROM
      role_mapping trm INNER JOIN prm ON prm.from_role_id = trm.to_role_id
    WHERE
      trm.deleted_at IS NULL
      AND trm.resource_id IN (WITH RECURSIVE m AS ( /* only resources that are in this role mapping's ancestor hierarchy */
      SELECT
        resource_id, parent_resource_id
      FROM
        resource
      WHERE 
        resource_id = trm.resource_id
        AND deleted_at IS NULL
      UNION SELECT
        p.resource_id, p.parent_resource_id
      FROM
        resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
      )
      SELECT 
        m.resource_id
      FROM
        m)
      )
    SELECT 
      prm.from_role_id,
      prm.to_role_id
    FROM
      prm) AS mappings
    CROSS JOIN LATERAL (
      VALUES (from_role_id), (to_role_id)
      ) AS rl (role_id))
  )`, identityID, identityID, resourceID, resourceID, scopeName, scopeName, resourceID).Scan(&results).Error

	if err != nil {
		return nil, errs.WithStack(err)
	}

	return results, nil
}

// FindIdentityRolesForIdentity returns an IdentityAssociations describing the roles which the specified Identity has, optionally for a specified resource type
func (m *GormIdentityRoleRepository) FindIdentityRolesForIdentity(ctx context.Context, identityID uuid.UUID, resourceType *string) ([]authorization.IdentityAssociation, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "FindIdentityRolesForIdentity"}, time.Now())
	associations := []authorization.IdentityAssociation{}

	// query for identities in which the user is a member
	q := m.db.Table(m.TableName()).
		Select("identity_role.resource_id AS ResourceID, r.name AS ResourceName, role.name AS RoleName, i.id AS IdentityID, r.parent_resource_id AS ParentResourceID").
		Joins("JOIN resource r ON r.resource_id = identity_role.resource_id").
		Joins("LEFT JOIN identities i ON r.resource_id = i.identity_resource_id").
		Joins("LEFT JOIN resource pr ON r.parent_resource_id = pr.resource_id")

	// with the specified resourceType
	if resourceType != nil {
		q = q.Joins("JOIN resource_type rt ON r.resource_type_id = rt.resource_type_id AND rt.name = ?", resourceType)
	}
	q = q.Joins("JOIN role ON role.role_id = identity_role.role_id")

	rows, err := q.Where(`(identity_role.identity_id = ? OR identity_role.identity_id IN (WITH RECURSIVE m AS (
			SELECT member_of FROM	membership WHERE member_id = ? 
      UNION SELECT p.member_of	FROM membership p INNER JOIN m ON m.member_of = p.member_id)
		  SELECT member_of FROM m))`, identityID, identityID).Rows()

	defer rows.Close()

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var resourceID string
		var resourceName string
		var roleName string
		var identityID uuid.UUID
		var parentResourceID string
		rows.Scan(&resourceID, &resourceName, &roleName, &identityID, &parentResourceID)
		associations = authorization.AppendAssociation(associations, resourceID, &resourceName, &parentResourceID, &identityID, false, &roleName)
	}

	return associations, nil
}

// FindIdentityRolesByResourceAndRoleName returns an array of IdentityRole objects that match the specified resource and role name
func (m *GormIdentityRoleRepository) FindIdentityRolesByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "FindIdentityRolesByResourceAndRoleName"}, time.Now())

	var identityRoles []IdentityRole

	err := m.db.Table(m.TableName()).Preload("Role").Preload("Resource").Preload("Identity").
		Where(`resource_id in (WITH RECURSIVE r AS (
      SELECT resource_id, parent_resource_id FROM resource WHERE resource_id = ?
      UNION SELECT p.resource_id, p.parent_resource_id FROM resource p INNER JOIN r ON r.parent_resource_id = p.resource_id)
	    SELECT r.resource_id FROM r)`, resourceID).
		Joins("JOIN role ON identity_role.role_id = role.role_id AND role.name = ?", roleName).Find(&identityRoles).Error

	if err != nil {
		return nil, err
	}

	return identityRoles, nil
}

// FindIdentityRolesByResource returns an array of IdentityRole for the specified resource
func (m *GormIdentityRoleRepository) FindIdentityRolesByResource(ctx context.Context, resourceID string) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "FindIdentityRolesByResource"}, time.Now())

	var identityRoles []IdentityRole

	err := m.db.Table(m.TableName()).Preload("Role").Preload("Resource").Preload("Identity").
		Where(`resource_id in (WITH RECURSIVE r AS (
      SELECT resource_id, parent_resource_id FROM resource WHERE resource_id = ?
      UNION SELECT p.resource_id, p.parent_resource_id FROM resource p INNER JOIN r ON r.parent_resource_id = p.resource_id)
	    SELECT r.resource_id FROM r)`, resourceID).
		Find(&identityRoles).Error

	if err != nil {
		return nil, err
	}

	return identityRoles, nil
}

// FindIdentityRolesByIdentityAndResource returns all identity roles by identity ID and resource ID
func (m *GormIdentityRoleRepository) FindIdentityRolesByIdentityAndResource(ctx context.Context, resourceID string, identityID uuid.UUID) ([]IdentityRole, error) {
	return m.query(identityRoleFilterByIdentityID(identityID), identityRoleFilterByResource(resourceID))
}

// Query exposes an open ended Query model
func (m *GormIdentityRoleRepository) query(funcs ...func(*gorm.DB) *gorm.DB) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var rows []IdentityRole
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"identity_roles": rows,
	}, "Identity query executed successfully!")

	return rows, nil
}

// IdentityRoleFilterByResource is a gorm filter for resource ID
func identityRoleFilterByResource(resourceID string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("resource_id = ?", resourceID)
	}
}

// IdentityRoleFilterByIdentityID is a gorm filter for Identity ID.
func identityRoleFilterByIdentityID(identityID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("identity_id = ?", identityID)
	}
}
