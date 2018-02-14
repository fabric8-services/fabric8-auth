package role

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	errs "github.com/pkg/errors"
)

type IdentityRole struct {
	gormsupport.Lifecycle

	// This is the primary key value
	IdentityRoleID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:identity_role_id"`
	// The identity to which the role is assigned
	IdentityID uuid.UUID
	Identity   account.Identity
	// The resource to which the role is applied
	ResourceID string
	Resource   resource.Resource
	// The role that is assigned
	RoleID uuid.UUID
	Role   Role
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
	repository.Exister
	Load(ctx context.Context, ID uuid.UUID) (*IdentityRole, error)
	Create(ctx context.Context, u *IdentityRole) error
	Save(ctx context.Context, u *IdentityRole) error
	List(ctx context.Context) ([]IdentityRole, error)
	ListAssignedRolesByResource(ctx context.Context, resourceID string) ([]IdentityRole, error)
	Delete(ctx context.Context, ID uuid.UUID) error
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
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
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

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_role_id": id,
			"err":              err,
		}, "unable to delete the identity role")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_role_id": id,
	}, "Identity role deleted!")

	return nil
}

// ListAssignedRolesByResource returns all assigned roles associated with a specific resource
func (m *GormIdentityRoleRepository) ListAssignedRolesByResource(ctx context.Context, resourceID string) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []IdentityRole

	m.db = m.db.Debug()
	db := m.db.Raw(`WITH RECURSIVE q AS ( 
		SELECT 
		  resource_id, parent_resource_id 
		FROM 
		  resource 
		WHERE 
		  resource_id = ?
		UNION ALL
		SELECT 
		  p.resource_id, p.parent_resource_id
		FROM 
		  resource p
		JOIN q ON 
		  q.parent_resource_id = p.resource_id)
	  SELECT 
		q.parent_resource_id,q.resource_id, ir.identity_role_id, ir.identity_id, r.role_id, r.name 
	  FROM 
		identity_role ir, q, role r
	  WHERE 
		ir.resource_id = q.resource_id 
		and ir.role_id = r.role_id`, resourceID)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error running custom sql to get identity roles")
		return identityRoles, err
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
			"resource_id": resourceID,
			"err":         err,
		}, "error getting columns")
		return identityRoles, errors.NewInternalError(ctx, err)
	}

	for rows.Next() {
		var parentResourceID *string
		var returnedResourceID string
		var identityRoleID string
		var identityID string
		var roleID string
		var roleName string

		columnValues[0] = &parentResourceID
		columnValues[1] = &returnedResourceID
		columnValues[2] = &identityRoleID
		columnValues[3] = &identityID
		columnValues[4] = &roleID
		columnValues[5] = &roleName

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "error getting rows")
			return identityRoles, errors.NewInternalError(ctx, err)
		}
		identityRoleIDAsUUID, _ := uuid.FromString(identityRoleID)
		identityIDAsUUID, _ := uuid.FromString(identityID)
		roleIDAsUUID, _ := uuid.FromString(roleID)

		ir := IdentityRole{
			IdentityRoleID: identityRoleIDAsUUID,
			Identity: account.Identity{
				ID: identityIDAsUUID,
			},
			Resource: resource.Resource{
				ResourceID:       resourceID,
				ParentResourceID: parentResourceID,
			},
			Role: Role{
				RoleID: roleIDAsUUID,
				Name:   roleName,
			},
		}
		if parentResourceID != nil {
			ir.Resource.ParentResourceID = parentResourceID
		}
		identityRoles = append(identityRoles, ir)
	}
	return identityRoles, nil

}

// List returns all identity roles
func (m *GormIdentityRoleRepository) List(ctx context.Context) ([]IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var rows []IdentityRole

	err := m.db.Model(&resource.ResourceType{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// IdentityRoleFilterByID is a gorm filter for Identity Role ID.
func IdentityRoleFilterByID(identityRoleID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("identity_role_id = ?", identityRoleID)
	}
}
