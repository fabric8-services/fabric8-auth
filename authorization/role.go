package authorization

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/application/repository"

	uuid "github.com/satori/go.uuid"
	errs "github.com/pkg/errors"
)

type Role struct {
	gormsupport.Lifecycle

	// This is the primary key value
	RoleID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key" gorm:"column:role_id"`
	// The resource type that this role applies to
	ResourceType ResourceType
	// The name of this role
	Name string
	// The description of this role
	Description string
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m Role) TableName() string {
	return "role"
}

// GetLastModified returns the last modification time
func (m Role) GetLastModified() time.Time {
	return m.UpdatedAt
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
	repository.Exister
	Load(ctx context.Context, ID uuid.UUID) (*Role, error)
	Create(ctx context.Context, u *Role) error
	Save(ctx context.Context, u *Role) error
	List(ctx context.Context) ([]Role, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Role, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormRoleRepository) TableName() string {
	return "role"
}

// CRUD Functions

// Load returns a single Role as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormRoleRepository) Load(ctx context.Context, id uuid.UUID) (*Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "load"}, time.Now())
	var native Role
	err := m.db.Table(m.TableName()).Where("role_id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("role", id.String())
	}
	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormRoleRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "role", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
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
			"err": err,
		}, "unable to create the role")
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
			"err": err,
		}, "unable to update role")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
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

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"role_id": id,
			"err": err,
		}, "unable to delete the role")
		return errs.WithStack(err)
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

	err := m.db.Model(&ResourceType{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Query expose an open ended Query model
func (m *GormRoleRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Role, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "query"}, time.Now())
	var objs []Role

	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&objs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	log.Debug(nil, map[string]interface{}{
		"role_list": objs,
	}, "Role query successfully executed!")

	return objs, nil
}

// RoleFilterByID is a gorm filter for Role ID.
func RoleFilterByID(roleID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("role_id = ?", roleID)
	}
}