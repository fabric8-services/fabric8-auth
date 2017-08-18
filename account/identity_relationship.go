package account

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"

	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type IdentityRelationship struct {
	gormsupport.Lifecycle

	ParentIdentity Identity `gorm:"primary_key"`
	ChildIdentity Identity `gorm:"primary_key"`
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m IdentityRelationship) TableName() string {
	return "identity_relationship"
}

// GetLastModified returns the last modification time
func (m IdentityRelationship) GetLastModified() time.Time {
	return m.UpdatedAt
}

// GormIdentityRelationshipRepository is the implementation of the storage interface for IdentityRelationship.
type GormIdentityRelationshipRepository struct {
	db *gorm.DB
}

// NewIdentityRelationshipRepository creates a new storage type.
func NewIdentityRelationshipeRepository(db *gorm.DB) IdentityRelationshipRepository {
	return &GormIdentityRelationshipRepository{db: db}
}

// IdentityRelationshipRepository represents the storage interface.
type IdentityRelationshipRepository interface {
	//repository.Exister
	Load(ctx context.Context, ParentIdentity Identity, ChildIdentity Identity) (*IdentityRelationship, error)
	Create(ctx context.Context, u *IdentityRelationship) error
	Save(ctx context.Context, u *IdentityRelationship) error
	List(ctx context.Context) ([]IdentityRelationship, error)
	Delete(ctx context.Context, parentIdentityID uuid.UUID, childIdentityID uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]IdentityRelationship, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormIdentityRelationshipRepository) TableName() string {
	return "identity_relationship"
}

// CRUD Functions

// Load returns a single IdentityRelationship as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormIdentityRelationshipRepository) Load(ctx context.Context, ParentIdentity Identity, ChildIdentity Identity) (*IdentityRelationship, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "load"}, time.Now())
	var native IdentityRelationship
	err := m.db.Table(m.TableName()).Where("parent_identity_id = ? and child_identity_id = ?", ParentIdentity.ID.String(), ChildIdentity.ID.String()).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.NewNotFoundError("identity_relationship", ParentIdentity.ID.String() + "," + ChildIdentity.ID.String())
	}
	return &native, errs.WithStack(err)
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormIdentityRelationshipRepository) CheckExists(ctx context.Context, parentIdentityID uuid.UUID, childIdentityID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "exists"}, time.Now())
	// TODO - CheckExists is bad code, makes assumption that there is only a singular primary key.. need to rewrite this
	// to work with a composite primary
	return repository.CheckExists(ctx, m.db, m.TableName(), parentIdentityID.String())
}

// Create creates a new record.
func (m *GormIdentityRelationshipRepository) Create(ctx context.Context, u *IdentityRelationship) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "create"}, time.Now())
	err := m.db.Create(u).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"parent_identity_id": u.ParentIdentity.ID,
			"child_identity_id": u.ChildIdentity.ID,
			"err": err,
		}, "unable to create the identity relationship")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"parent_identity_id": u.ParentIdentity.ID,
		"child_identity_id": u.ChildIdentity.ID,
	}, "Identity relationship created!")
	return nil
}

// Save modifies a single record
func (m *GormIdentityRelationshipRepository) Save(ctx context.Context, model *IdentityRelationship) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "save"}, time.Now())

	obj, err := m.Load(ctx, model.ParentIdentity, model.ChildIdentity)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"parent_identity_id": model.ParentIdentity.ID.String(),
			"child_identity_id": model.ChildIdentity.ID.String(),
			"err": err,
		}, "unable to update identity relationship")
		return errs.WithStack(err)
	}
	err = m.db.Model(obj).Updates(model).Error
	if err != nil {
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"parent_identity_id": model.ParentIdentity.ID.String(),
		"child_identity_id": model.ChildIdentity.ID.String(),
	}, "Identity relationship saved!")
	return nil
}

// Delete removes a single record.
func (m *GormIdentityRelationshipRepository) Delete(ctx context.Context, parentIdentityID uuid.UUID, childIdentityID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "delete"}, time.Now())

	obj := IdentityRelationship{ParentIdentity:Identity{ID: parentIdentityID}, ChildIdentity: Identity{ID: childIdentityID}}

	err := m.db.Delete(&obj).Error

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"parent_identity_id": parentIdentityID,
			"child_identity_id": childIdentityID,
			"err": err,
		}, "unable to delete the identity relationship")
		return errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"parent_identity_id": parentIdentityID,
		"child_identity_id": childIdentityID,
	}, "Identity relationship deleted!")

	return nil
}

// List returns all identity relationships
func (m *GormIdentityRelationshipRepository) List(ctx context.Context) ([]IdentityRelationship, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "list"}, time.Now())
	var rows []IdentityRelationship

	err := m.db.Model(&IdentityRelationship{}).Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	return rows, nil
}

// Query expose an open ended Query model
func (m *GormIdentityRelationshipRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]IdentityRelationship, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_relationship", "query"}, time.Now())
	var objs []IdentityRelationship

	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&objs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	log.Debug(nil, map[string]interface{}{
		"identity_relationship_list": objs,
	}, "Identity relationship query successfully executed!")

	return objs, nil
}

// IdentityRelationshipFilterByID is a gorm filter for Parent Identity ID and Child Identity ID.
func IdentityRelationshipFilterByID(parentIdentityID uuid.UUID, childIdentityID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("parent_identity_ = ? and child_identity_id = ?", parentIdentityID, childIdentityID)
	}
}