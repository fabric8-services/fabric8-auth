package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository/base"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type Role struct {
	gormsupport.Lifecycle

	// This is the primary key value
	RoleID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key;column:role_id"`
	// The resource type that this role applies to
	ResourceType resourcetype.ResourceType `gorm:"ForeignKey:ResourceTypeID;AssociationForeignKey:ResourceTypeID"`
	// The foreign key value for ResourceType
	ResourceTypeID uuid.UUID
	// The name of this role
	Name string
}

// GormRoleRepository is the implementation of the storage interface for Role.
type GormRoleRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates a new storage type.
func NewRoleRepository(db *gorm.DB) RoleRepository {
	return &GormRoleRepository{db: db}
}

// RoleRepository represents the storage interface.
type RoleRepository interface {
	CheckExists(ctx context.Context, id string) error
	Load(ctx context.Context, ID uuid.UUID) (*Role, error)
	Create(ctx context.Context, u *Role) error
	Save(ctx context.Context, u *Role) error
	List(ctx context.Context) ([]Role, error)
	Delete(ctx context.Context, ID uuid.UUID) error

	Lookup(ctx context.Context, name string, resourceType string) (*Role, error)
	ListScopes(ctx context.Context, u *Role) ([]resourcetype.ResourceTypeScope, error)
	AddScope(ctx context.Context, u *Role, s *resourcetype.ResourceTypeScope) error

	FindRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	FindRolesByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]role.ResourceRoleDescriptor, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleRepository) TableName() string {
	return "role"
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m Role) TableName() string {
	return "role"
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormRoleRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "exists"}, time.Now())
	return base.CheckExistsWithCustomIDColumn(ctx, m.db, m.TableName(), "role_id", id)
}

// CRUD Functions

// Load returns a single Role as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormRoleRepository) Load(ctx context.Context, id uuid.UUID) (*Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "load"}, time.Now())
	var native Role
	err := m.db.Table(m.TableName()).Preload("ResourceType"). /*.Preload("Scopes")*/ Where("role_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("role", id.String())
	}
	return &native, errs.WithStack(err)
}

// Create creates a new record.
func (m *GormRoleRepository) Create(ctx context.Context, u *Role) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "create"}, time.Now())
	if u.RoleID == uuid.Nil {
		u.RoleID = uuid.NewV4()
	}
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_id": u.RoleID,
			"err":     err,
		}, "unable to create the role")
		if gormsupport.IsUniqueViolation(err, "uq_role_resource_type_name") {
			log.Error(ctx, map[string]interface{}{
				"err":              err,
				"role_name":        u.Name,
				"resource_type_id": u.ResourceTypeID,
			}, "unable to create role because the same role already exists for this resource_type")
			return errors.NewDataConflictError(fmt.Sprintf("role already exists with name = %s , resource_type_id = %s ", u.Name, u.ResourceTypeID.String()))
		}
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"role_id": u.RoleID,
	}, "Role created!")
	return nil
}

// Save modifies a single record
func (m *GormRoleRepository) Save(ctx context.Context, model *Role) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "save"}, time.Now())

	obj, err := m.Load(ctx, model.RoleID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_id": model.RoleID,
			"err":     err,
		}, "unable to update role")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		if gormsupport.IsUniqueViolation(err, "uq_role_resource_type_name") {
			log.Error(ctx, map[string]interface{}{
				"err":              err,
				"role_name":        model.Name,
				"resource_type_id": model.ResourceTypeID,
			}, "unable to create role because the same role already exists for this resource_type")
			return errors.NewDataConflictError(fmt.Sprintf("role already exists with name = %s , resource_type_id = %s ", model.Name, model.ResourceTypeID.String()))
		}
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"role_id": model.RoleID,
	}, "Role saved!")
	return nil
}

// Delete removes a single record.
func (m *GormRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "delete"}, time.Now())

	obj := Role{RoleID: id}

	result := m.db.Delete(&obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"role_id": id,
			"err":     result.Error,
		}, "unable to delete the role")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("role", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"role_id": id,
	}, "Role deleted!")

	return nil
}

// List returns all roles
func (m *GormRoleRepository) List(ctx context.Context) ([]Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "list"}, time.Now())
	var rows []Role

	err := m.db.Model(&Role{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

func (m *GormRoleRepository) Lookup(ctx context.Context, name string, resourceType string) (*Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "lookup"}, time.Now())

	var native Role
	err := m.db.Table(m.TableName()).Joins(
		"left join resource_type on resource_type.resource_type_id = role.resource_type_id").Preload(
		"ResourceType").Where("role.name = ? and resource_type.name = ?", name, resourceType).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundErrorWithKey("role", "name", name)
	}
	return &native, errs.WithStack(err)
}

func (m *GormRoleRepository) ListScopes(ctx context.Context, u *Role) ([]resourcetype.ResourceTypeScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "listscopes"}, time.Now())

	var scopes []RoleScope

	err := m.db.Table("role_scope").Where("role_id = ?", u.RoleID.String()).Preload("ResourceTypeScope").Find(&scopes).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	results := make([]resourcetype.ResourceTypeScope, len(scopes))
	for index := 0; index < len(scopes); index++ {
		results[index] = scopes[index].ResourceTypeScope
	}

	return results, nil
}

func (m *GormRoleRepository) AddScope(ctx context.Context, u *Role, s *resourcetype.ResourceTypeScope) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "addscope"}, time.Now())

	roleScope := &RoleScope{
		RoleID:              u.RoleID,
		ResourceTypeScope:   *s,
		ResourceTypeScopeID: s.ResourceTypeScopeID,
	}

	err := m.db.Create(roleScope).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_id":  u.RoleID,
			"scope_id": s.ResourceTypeScopeID,
			"err":      err,
		}, "unable to create the role scope")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"role_id":  u.RoleID,
		"scope_id": s.ResourceTypeScopeID,
	}, "Role scope created!")
	return nil
}

func (m *GormRoleRepository) FindRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "FindRolesByResourceType"}, time.Now())
	var roles []role.RoleDescriptor

	db := m.db.Raw(`SELECT r.role_id,
		r.name role_name,
		array_to_string(array_agg(rts.NAME), ',') scopes
		FROM   
		  role r LEFT OUTER JOIN role_scope rs ON r.role_id = rs.role_id
		  LEFT OUTER JOIN resource_type_scope rts ON rs.scope_id = rts.resource_type_scope_id,
			resource_type rt
		WHERE  
			rt.resource_type_id = r.resource_type_id 
      AND r.deleted_at IS NULL
			AND rt.NAME = ?
      AND rt.deleted_at IS NULL
		GROUP BY 
		  r.role_id, 
		  r.name`, resourceType)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resourceType": resourceType,
			"err":          err,
		}, "error running custom sql to get available roles")
		return roles, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	columnValues := make([]interface{}, len(columns))

	var ignore interface{}
	for index := range columnValues {
		columnValues[index] = &ignore
	}

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": resourceType,
			"err":           err,
		}, "error getting columns")
		return roles, errors.NewInternalError(ctx, err)
	}

	for rows.Next() {
		var roleName string
		var scopeNames string
		var roleID string

		columnValues[0] = &roleID
		columnValues[1] = &roleName
		columnValues[2] = &scopeNames

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": resourceType,
				"err":           err,
			}, "error getting rows")
			return roles, errors.NewInternalError(ctx, err)
		}
		var scopesList []string
		if scopeNames != "" {
			scopesList = strings.Split(scopeNames, ",")
		}
		roleScope := role.RoleDescriptor{
			RoleName:     roleName,
			RoleID:       roleID,
			Scopes:       scopesList,
			ResourceType: resourceType,
		}
		roles = append(roles, roleScope)
	}
	return roles, err
}

func (m *GormRoleRepository) FindRolesByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]role.ResourceRoleDescriptor, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "FindRolesByResourceTypeAndIdentity"}, time.Now())
	var result []role.ResourceRoleDescriptor

	db := m.db.Raw(`
		/* list all resources with their type and their ancestor (whatever level) */
		WITH RECURSIVE all_resources AS ( 
			SELECT r.resource_id, r.resource_type_id, r.parent_resource_id as ancestor_resource_id 
			FROM resource r INNER JOIN resource_type rt on r.resource_type_id = rt.resource_type_id 
			WHERE rt.name = $2 /* limit to resources of the given type */
			UNION SELECT r.resource_id, r.resource_type_id, a.ancestor_resource_id  
			FROM resource r INNER JOIN all_resources a ON r.parent_resource_id = a.resource_id
			WHERE a.ancestor_resource_id IS NOT NULL
		),
		/* list the identities of the teams to which the current user belongs, plus herself's identity */
		teams AS ( 
			SELECT member_of as "id"
			FROM membership
			WHERE member_id = $1 /* user's identity */
			UNION SELECT m.member_of
			FROM membership m INNER JOIN teams ON teams.id = m.member_id
		)

		/* list the roles on resources of the given type when the user has a direct role */
		SELECT role.role_id, role.name role_name, res.resource_id, array_to_string(array_agg(rts.NAME), ',') scopes
		FROM identity_role ir
			INNER JOIN role ON role.role_id = ir.role_id
			INNER JOIN role_scope rs ON rs.role_id = role.role_id
			INNER JOIN resource_type_scope rts ON rts.resource_type_scope_id = rs.scope_id
			INNER JOIN resource res ON res.resource_id = ir.resource_id
			INNER JOIN resource_type rt ON rt.resource_type_id = res.resource_type_id
		WHERE rt.name = $2 /* filter on given resource type */
			AND ir.identity_id IN ( /* look-up users alone or as a member of a team */
				SELECT $1
				UNION SELECT teams.id from teams
			)
			AND role.deleted_at IS NULL
			AND rs.deleted_at IS NULL
			AND rts.deleted_at IS NULL
        	AND ir.deleted_at IS NULL
		GROUP BY 
		  	role.role_id, role.name, res.resource_id
		/* list the roles on resources of the given type when the user has a role inherited by an ancestor resource via default role mapping */
		UNION
		SELECT inherited_role.role_id, inherited_role.name role_name, inherited_res.resource_id, array_to_string(array_agg(rts.NAME), ',') scopes
		FROM identity_role ir
			INNER JOIN role via_role ON via_role.role_id = ir.role_id
			INNER JOIN all_resources ar ON ir.resource_id = ar.ancestor_resource_id
			INNER JOIN resource inherited_res ON inherited_res.resource_id = ar.resource_id
			INNER JOIN resource_type inherited_rt ON inherited_rt.resource_type_id = inherited_res.resource_type_id
			INNER JOIN default_role_mapping drm on (ir.role_id = drm.from_role_id AND drm.resource_type_id = inherited_res.resource_type_id)
			INNER JOIN role inherited_role on drm.to_role_id = inherited_role.role_id
			INNER JOIN role_scope rs ON rs.role_id = drm.to_role_id
			INNER JOIN resource_type_scope rts ON rts.resource_type_scope_id = rs.scope_id
		WHERE inherited_rt.name = $2 /* filter on given resource type */
			AND ir.identity_id IN ( /* look-up users alone or as a member of a team */
				SELECT $1
				UNION SELECT teams.id from teams
			)
			AND inherited_role.deleted_at IS NULL
			AND rs.deleted_at IS NULL
			AND rts.deleted_at IS NULL
        	AND ir.deleted_at IS NULL
		GROUP BY 
			inherited_role.role_id, inherited_role.name, inherited_res.resource_id
		  `, identityID, resourceType)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resourceType": resourceType,
			"err":          err,
		}, "error running custom sql to get available roles")
		return result, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	columnValues := make([]interface{}, len(columns))

	var ignore interface{}
	for index := range columnValues {
		columnValues[index] = &ignore
	}

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": resourceType,
			"err":           err,
		}, "error getting columns")
		return result, errors.NewInternalError(ctx, err)
	}

	for rows.Next() {
		var roleName string
		var scopeNames string
		var roleID string
		var resourceID string

		columnValues[0] = &roleID
		columnValues[1] = &roleName
		columnValues[2] = &resourceID
		columnValues[3] = &scopeNames

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": resourceType,
				"err":           err,
			}, "error getting rows")
			return result, errors.NewInternalError(ctx, err)
		}
		var scopesList []string
		if scopeNames != "" {
			scopesList = strings.Split(scopeNames, ",")
		}
		item := role.ResourceRoleDescriptor{
			RoleName:     roleName,
			RoleID:       roleID,
			Scopes:       scopesList,
			ResourceID:   resourceID,
			ResourceType: resourceType,
		}
		result = append(result, item)
	}
	return result, err
}
