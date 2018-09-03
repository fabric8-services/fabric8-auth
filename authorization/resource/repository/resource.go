package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository/base"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type Resource struct {
	gormsupport.Lifecycle

	// This is the primary key value
	ResourceID string `sql:"type:string" gorm:"primary_key;column:resource_id"`
	// The parent resource ID
	ParentResourceID *string
	// The parent resource
	ParentResource *Resource `gorm:"foreignkey:ParentResourceID;association_foreignkey:ResourceID"`
	// The resource type
	ResourceType resourcetype.ResourceType `gorm:"foreignkey:ResourceTypeID;association_foreignkey:ResourceTypeID"`
	// The identifier for the resource type
	ResourceTypeID uuid.UUID
	// Resource name
	Name string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m Resource) TableName() string {
	return "resource"
}

// GetLastModified returns the last modification time
func (m Resource) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormResourceRepository is the implementation of the storage interface for Resource.
type GormResourceRepository struct {
	db               *gorm.DB
	resourceTypeRepo resourcetype.ResourceTypeRepository
}

// NewResourceRepository creates a new storage type.
func NewResourceRepository(db *gorm.DB) ResourceRepository {
	return &GormResourceRepository{db: db, resourceTypeRepo: resourcetype.NewResourceTypeRepository(db)}
}

// ResourceRepository represents the storage interface.
type ResourceRepository interface {
	base.Exister
	Load(ctx context.Context, id string) (*Resource, error)
	LoadChildren(ctx context.Context, id string) ([]Resource, error)
	Create(ctx context.Context, resource *Resource) error
	Save(ctx context.Context, resource *Resource) error
	Delete(ctx context.Context, id string) error
	FindWithRoleByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]string, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormResourceRepository) TableName() string {
	return "resource"
}

// CRUD Functions

// Load returns a single Resource as a Database Model
func (m *GormResourceRepository) Load(ctx context.Context, id string) (*Resource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "load"}, time.Now())

	var native Resource
	err := m.db.Table(m.TableName()).Preload("ResourceType").Where("resource_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("resource", id))
	}

	return &native, errs.WithStack(err)
}

// LoadChildren returns direct children resources of the given resource or an empty array if no children found
func (m *GormResourceRepository) LoadChildren(ctx context.Context, id string) ([]Resource, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "loadChildren"}, time.Now())

	var rows []Resource
	err := m.db.Model(&Resource{}).Preload("ResourceType").Where("parent_resource_id = ?", id).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormResourceRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "exists"}, time.Now())
	return base.CheckExistsWithCustomIDColumn(ctx, m.db, m.TableName(), "resource_id", id)
}

// Create creates a new record.
func (m *GormResourceRepository) Create(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "create"}, time.Now())

	// If no identifier has been specified for the new resource, then generate one
	if resource.ResourceID == "" {
		resource.ResourceID = uuid.NewV4().String()
	}

	if resource.ResourceTypeID.String() == "" {
		resourceType, err := m.resourceTypeRepo.Lookup(ctx, resource.ResourceType.Name)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": resource.ResourceType.Name,
				"err":           err,
			}, "unable to find the resource type")
			return errs.WithStack(err)
		}
		resource.ResourceTypeID = resourceType.ResourceTypeID
	}

	err := m.db.Create(resource).Error
	if err != nil {
		// Organization names must be unique
		if gormsupport.IsUniqueViolation(err, "unique_organization_names") {
			log.Error(ctx, map[string]interface{}{
				"err":  err,
				"name": resource.Name,
			}, "unable to create organization resource as an organization with the same name already exists")
			return errors.NewDataConflictError(fmt.Sprintf("organization with same name already exists, '%s'", resource.Name))
		}
		if gormsupport.IsUniqueViolation(err, "resource_pkey") {
			return errors.NewDataConflictError(fmt.Sprintf("resource with ID %s already exists", resource.ResourceID))
		}

		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ResourceID,
			"err":         err,
		}, "unable to create the resource")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"resource_id": resource.ResourceID,
	}, "Resource created!")
	return nil
}

// Save modifies a single record.
func (m *GormResourceRepository) Save(ctx context.Context, resource *Resource) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "save"}, time.Now())

	err := m.db.Save(resource).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resource.ResourceID,
			"err":         err,
		}, "unable to update the resource")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_id": resource.ResourceID,
	}, "Resource saved!")

	return nil
}

// Delete removes a single record.
func (m *GormResourceRepository) Delete(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "delete"}, time.Now())

	obj := Resource{ResourceID: id}
	result := m.db.Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": id,
			"err":         result.Error,
		}, "unable to delete the resource")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("resource", id)
	}

	log.Debug(ctx, map[string]interface{}{
		"resource_id": id,
	}, "Resource deleted!")

	return nil
}

// FindWithRoleByResourceTypeAndIdentity returns the IDs of the resources of the given type for which the given user (identity) has a role in.
func (m *GormResourceRepository) FindWithRoleByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]string, error) {
	defer goa.MeasureSince([]string{"goa", "db", "resource", "FindWithRoleByResourceTypeAndIdentity"}, time.Now())
	var result []string
	db := m.db.Raw(`
		/* list all resources with their type and their ancestor (whatever level) */
		WITH RECURSIVE all_resources AS ( 
			SELECT r.resource_id, r.resource_type_id, r.parent_resource_id as ancestor_resource_id 
			FROM resource r INNER JOIN resource_type rt on r.resource_type_id = rt.resource_type_id 
			WHERE rt.name = $2 /* limit to resources of the given type */
			UNION SELECT r.resource_id, r.resource_type_id, a.ancestor_resource_id  
			FROM resource r INNER JOIN all_resources a ON r.parent_resource_id = a.resource_id
			WHERE a.ancestor_resource_id IS NOT NULL
			  AND r.deleted_at IS NULL
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
		SELECT res.resource_id
		FROM identity_role ir
			INNER JOIN role ON role.role_id = ir.role_id
			INNER JOIN resource res ON res.resource_id = ir.resource_id
			INNER JOIN resource_type rt ON rt.resource_type_id = res.resource_type_id
		WHERE rt.name = $2 /* filter on given resource type */
			AND ir.identity_id IN ( /* look-up users alone or as a member of a team */
				SELECT $1
				UNION SELECT teams.id from teams
			)
			AND res.deleted_at IS NULL
			AND role.deleted_at IS NULL
			AND ir.deleted_at IS NULL
		/* list the roles on resources of the given type when the user has a role inherited from an ancestor resource via default role mapping */
		UNION
		SELECT inherited_res.resource_id
		FROM identity_role ir
			INNER JOIN role via_role ON via_role.role_id = ir.role_id
			INNER JOIN all_resources ar ON ir.resource_id = ar.ancestor_resource_id
			INNER JOIN resource inherited_res ON inherited_res.resource_id = ar.resource_id
			INNER JOIN resource_type inherited_rt ON inherited_rt.resource_type_id = inherited_res.resource_type_id
			INNER JOIN default_role_mapping drm on (ir.role_id = drm.from_role_id AND drm.resource_type_id = inherited_res.resource_type_id)
			INNER JOIN role inherited_role on drm.to_role_id = inherited_role.role_id
		WHERE inherited_rt.name = $2 /* filter on given resource type */
			AND ir.identity_id IN ( /* look-up users alone or as a member of a team */
				SELECT $1
				UNION SELECT teams.id from teams
			)
        	AND ir.deleted_at IS NULL
			AND via_role.deleted_at IS NULL
			AND inherited_res.deleted_at IS NULL
			AND drm.deleted_at IS NULL
			AND inherited_role.deleted_at IS NULL`,
		identityID, resourceType)

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
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": resourceType,
			"err":           err,
		}, "error getting columns")
		return result, errors.NewInternalError(ctx, err)
	}
	columnValues := make([]interface{}, len(columns))

	var ignore interface{}
	for index := range columnValues {
		columnValues[index] = &ignore
	}

	for rows.Next() {
		var resourceID string
		if err = rows.Scan(&resourceID); err != nil {
			return result, errs.Wrapf(err, "failed to read database record")
		}
		result = append(result, resourceID)
	}
	return result, err
}
