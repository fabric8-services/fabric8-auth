package account

import (
	"context"
	"database/sql/driver"
	"strconv"
	"time"

	repository "github.com/fabric8-services/fabric8-auth/application/repository/base"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"database/sql"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"strings"
)

const (
	// KeycloakIDP is the name of the main Keycloak Identity Provider
	KeycloakIDP string = "kc"
)

// NullUUID can be used with the standard sql package to represent a
// UUID value that can be NULL in the database
type NullUUID struct {
	UUID  uuid.UUID
	Valid bool
}

// Scan implements the sql.Scanner interface.
func (u *NullUUID) Scan(src interface{}) error {
	if src == nil {
		u.UUID, u.Valid = uuid.Nil, false
		return nil
	}

	// Delegate to UUID Scan function
	u.Valid = true

	switch src := src.(type) {
	case uuid.UUID:
		return u.UUID.Scan(src.Bytes())
	}

	return u.UUID.Scan(src)
}

// Value implements the driver.Valuer interface.
func (u NullUUID) Value() (driver.Value, error) {
	if !u.Valid {
		return nil, nil
	}
	// Delegate to UUID Value function
	return u.UUID.Value()
}

// Identity describes a federated identity provided by Identity Provider (IDP) such as Keycloak, GitHub, OSO, etc.
// One User account can have many Identities
type Identity struct {
	gormsupport.Lifecycle
	// This is the ID PK field. For identities provided by Keycloak this ID equals to the Keycloak. For other types of IDP (github, oso, etc) this ID is generated automaticaly
	ID uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"`
	// The username of the Identity
	Username string
	// Whether username has been updated.
	RegistrationCompleted bool `gorm:"column:registration_completed"`
	// ProviderType The type of provider, such as "keycloak", "github", "oso", etc
	ProviderType string `gorm:"column:provider_type"`
	// the URL of the profile on the remote work item service
	ProfileURL *string `gorm:"column:profile_url"`
	// Link to User
	UserID NullUUID `sql:"type:uuid"`
	User   User
	// Link to Resource
	IdentityResourceID sql.NullString
	IdentityResource   resource.Resource
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m Identity) TableName() string {
	return "identities"
}

// GetETagData returns the field values to use to generate the ETag
func (m Identity) GetETagData() []interface{} {
	// using the 'ID' and 'UpdatedAt' (converted to number of seconds since epoch) fields
	return []interface{}{m.ID, strconv.FormatInt(m.UpdatedAt.Unix(), 10)}
}

// GetLastModified returns the last modification time
func (m Identity) GetLastModified() time.Time {
	return m.UpdatedAt
}

func (m Identity) IsUser() bool {
	return m.UserID.Valid
}

// GormIdentityRepository is the implementation of the storage interface for
// Identity.
type GormIdentityRepository struct {
	db *gorm.DB
}

// NewIdentityRepository creates a new storage type.
func NewIdentityRepository(db *gorm.DB) *GormIdentityRepository {
	return &GormIdentityRepository{db: db}
}

// IdentityRepository represents the storage interface.
type IdentityRepository interface {
	repository.Exister
	Load(ctx context.Context, id uuid.UUID) (*Identity, error)
	LoadWithUser(ctx context.Context, id uuid.UUID) (*Identity, error)
	Create(ctx context.Context, identity *Identity) error
	Lookup(ctx context.Context, username, profileURL, providerType string) (*Identity, error)
	Save(ctx context.Context, identity *Identity) error
	Delete(ctx context.Context, id uuid.UUID) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Identity, error)
	List(ctx context.Context) ([]Identity, error)
	IsValid(context.Context, uuid.UUID) bool
	Search(ctx context.Context, q string, start int, limit int) ([]Identity, int, error)
	FindIdentityMemberships(ctx context.Context, identityID uuid.UUID, resourceType *string) ([]authorization.IdentityAssociation, error)
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormIdentityRepository) TableName() string {
	return "identities"

}

// CRUD Functions

// Load returns a single Identity as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *GormIdentityRepository) Load(ctx context.Context, id uuid.UUID) (*Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "load"}, time.Now())

	var native Identity
	err := m.db.Table(m.TableName()).Where("id = ?", id).Find(&native).Error
	if err == gorm.ErrRecordNotFound {
		return nil, errs.WithStack(errors.NewNotFoundError("identity", id.String()))
	}

	return &native, errs.WithStack(err)
}

// LoadWithUser loads an identity and the associated User
// Returns NotFoundError if either identity or user is not found
func (m *GormIdentityRepository) LoadWithUser(ctx context.Context, id uuid.UUID) (*Identity, error) {
	identities, err := m.Query(IdentityFilterByID(id), IdentityWithUser())
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, errs.WithStack(errors.NewNotFoundError("identity", id.String()))
	}
	if identities[0].User.ID == uuid.Nil {
		return nil, errs.WithStack(errors.NewNotFoundError("user for identity", id.String()))
	}
	return &identities[0], nil
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m *GormIdentityRepository) CheckExists(ctx context.Context, id string) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "exists"}, time.Now())
	return repository.CheckExists(ctx, m.db, m.TableName(), id)
}

// Create creates a new record.
func (m *GormIdentityRepository) Create(ctx context.Context, model *Identity) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "create"}, time.Now())
	if model.ID == uuid.Nil {
		model.ID = uuid.NewV4()
	}
	err := m.db.Create(model).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": model.ID,
			"err":         err,
		}, "unable to create the identity")
		return errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"identity_id": model.ID,
	}, "Identity created!")
	return nil
}

// Lookup looks for an existing identity with the given `profileURL` or creates a new one
func (m *GormIdentityRepository) Lookup(ctx context.Context, username, profileURL, providerType string) (*Identity, error) {
	if username == "" || profileURL == "" || providerType == "" {
		return nil, errs.New("Cannot lookup identity with empty username, profile URL or provider type")
	}
	log.Debug(nil, nil, "Looking for identity of user with profile URL=%s\n", profileURL)
	// bind the assignee to an existing identity, or create a new one
	identity, err := m.First(IdentityFilterByProfileURL(profileURL))
	if err != nil {
		return nil, errs.Wrapf(err, "failed to lookup identity by profileURL '%s'", profileURL)
	}
	if identity == nil {
		// create the identity if it does not exist yet
		log.Debug(nil, nil, "Creating an identity for username '%s' with profile '%s' on '%s'\n", username, profileURL, providerType)
		identity = &Identity{
			ProviderType: providerType,
			Username:     username,
			ProfileURL:   &profileURL,
		}
		err = m.Create(context.Background(), identity)
		if err != nil {
			return nil, errs.Wrap(err, "failed to create identity during lookup")
		}
	} else {
		// use existing identity
		log.Debug(nil, nil, "Using existing identity with ID: %v", identity.ID.String())
	}
	log.Debug(nil, nil, "Found identity of user with profile URL=%s: %s", profileURL, identity.ID)
	return identity, nil
}

// Save modifies a single record.
func (m *GormIdentityRepository) Save(ctx context.Context, model *Identity) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "save"}, time.Now())

	err := m.db.Save(model).Error

	log.Debug(ctx, map[string]interface{}{
		"identity_id": model.ID,
	}, "Identity saved!")

	return errs.WithStack(err)
}

// Delete removes a single record.
func (m *GormIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "delete"}, time.Now())

	obj := Identity{ID: id}
	db := m.db.Delete(obj)

	if db.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": id,
			"err":         db.Error,
		}, "unable to delete the identity")
		return errs.WithStack(db.Error)
	}
	if db.RowsAffected == 0 {
		return errors.NewNotFoundError("identity", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_id": id,
	}, "Identity deleted!")

	return nil
}

// Query expose an open ended Query model
func (m *GormIdentityRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "query"}, time.Now())
	var identities []Identity
	err := m.db.Scopes(funcs...).Table(m.TableName()).Find(&identities).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Debug(nil, map[string]interface{}{
		"identity_query": identities,
	}, "Identity query executed successfully!")

	return identities, nil
}

// First returns the first Identity element that matches the given criteria
func (m *GormIdentityRepository) First(funcs ...func(*gorm.DB) *gorm.DB) (*Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "first"}, time.Now())
	var objs []*Identity
	log.Debug(nil, nil, "Looking for identity matching: %v", funcs)

	err := m.db.Scopes(funcs...).Table(m.TableName()).First(&objs).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	if len(objs) != 0 && objs[0] != nil {
		log.Debug(nil, map[string]interface{}{
			"identity_list": objs,
		}, "Found matching identity: %v", *objs[0])
		return objs[0], nil
	}
	log.Debug(nil, map[string]interface{}{
		"identity_list": objs,
	}, "No matching identity found")
	return nil, nil
}

// IdentityFilterByUserID is a gorm filter for a Belongs To relationship.
func IdentityFilterByUserID(userID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("user_id = ?", userID)
	}
}

// IdentityFilterByUsername is a gorm filter by 'username'
func IdentityFilterByUsername(username string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("username = ?", username).Limit(1)
	}
}

// IdentityFilterByProfileURL is a gorm filter by 'profile_url'
func IdentityFilterByProfileURL(profileURL string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("profile_url = ?", profileURL).Limit(1)
	}
}

// IdentityFilterByID is a gorm filter for Identity ID.
func IdentityFilterByID(identityID uuid.UUID) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("id = ?", identityID)
	}
}

// IdentityWithUser is a gorm filter for preloading the User relationship.
func IdentityWithUser() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Preload("User")
	}
}

// IdentityFilterByProviderType is a gorm filter by 'provider_type'
func IdentityFilterByProviderType(providerType string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("provider_type = ?", providerType)
	}
}

// List return all user identities
func (m *GormIdentityRepository) List(ctx context.Context) ([]Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "list"}, time.Now())
	var rows []Identity

	err := m.db.Model(&Identity{}).Order("username").Find(&rows).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_list": &rows,
	}, "Identity List executed successfully!")

	return rows, nil
}

// IsValid returns true if the identity exists
func (m *GormIdentityRepository) IsValid(ctx context.Context, id uuid.UUID) bool {
	_, err := m.Load(ctx, id)
	if err != nil {
		return false
	}
	return true
}

// Search searches for Identities where FullName like %q% or users.email like %q% (but ignores private emails)
// or users.username like %q%
func (m *GormIdentityRepository) Search(ctx context.Context, q string, start int, limit int) ([]Identity, int, error) {
	paramVal := strings.ToLower(q) + "%"
	db := m.db

	queryStr := `SELECT count(*) OVER () as cnt2, identity_id, username, users.* FROM (SELECT 
  identities.id AS identity_id,
  identities.username,  
  users.*
FROM 
  identities, users
WHERE 
  identities.user_id = users.id 
  AND identities.username LIKE ?
  AND users.deprovisioned IS false
  AND users.deleted_at IS null
UNION SELECT
  identities.id AS identity_id,
  identities.username,
  users.*
FROM
  identities, users
WHERE  
  identities.user_id = users.id 
  AND users.deprovisioned IS false 
  AND (LOWER(users.full_name) LIKE ?
  OR (LOWER(users.email) LIKE ? AND users.email_private is false))) users LIMIT ?`

	rows, err := db.Raw(queryStr, paramVal, paramVal, paramVal, strconv.Itoa(limit)).Rows()

	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	result := []Identity{}
	value := Identity{}
	columns, err := rows.Columns()
	if err != nil {
		return nil, 0, errors.NewInternalError(ctx, err)
	}

	// need to set up a result for Scan() in order to extract total count.
	var count int
	var identityID string
	var identityUsername string
	var ignore interface{}
	columnValues := make([]interface{}, len(columns))

	for index := range columnValues {
		columnValues[index] = &ignore
	}
	columnValues[0] = &count
	// FIXME When our User Profile endpoints start giving "user" response
	// instead of "identity" response, the identity.ID would be less relevant.

	for rows.Next() {
		columnValues[1] = &identityID
		columnValues[2] = &identityUsername
		db.ScanRows(rows, &value.User)

		if err = rows.Scan(columnValues...); err != nil {
			return nil, 0, errors.NewInternalError(ctx, err)
		}

		value.ID, err = uuid.FromString(identityID)
		if err != nil {
			return nil, 0, errors.NewInternalError(ctx, err)
		}

		value.Username = identityUsername

		result = append(result, value)
	}

	return result, count, nil
}

// FindIdentityMemberships returns an array of Identity objects with the (optionally) specified resource type in which the specified Identity is a member
func (m *GormIdentityRepository) FindIdentityMemberships(ctx context.Context, identityID uuid.UUID, resourceType *string) ([]authorization.IdentityAssociation, error) {
	associations := []authorization.IdentityAssociation{}

	var identities []Identity

	// query for identities in which the user is a member
	q := m.db.Table(m.TableName())

	// with the specified resourceType
	if resourceType != nil {
		q = q.Joins("JOIN resource r ON r.resource_id = identities.identity_resource_id").
			Joins("JOIN resource_type rt ON r.resource_type_id = rt.resource_type_id AND rt.name = ?", resourceType)
	}

	err := q.Where(`identities.id IN (WITH RECURSIVE m AS (
			SELECT member_of FROM	membership WHERE member_id = ? 
      UNION SELECT p.member_of	FROM membership p INNER JOIN m ON m.member_of = p.member_id)
		  SELECT member_of FROM m)`, identityID).
		Find(&identities).Error

	if err != nil {
		return nil, err
	}

	// For each identity found, load its resource if it has one
	for _, identity := range identities {
		if identity.IdentityResourceID.Valid {
			err = m.db.Table("resource").Where("resource_id = ?", identity.IdentityResourceID).Find(&identity.IdentityResource).Error

			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.NewInternalErrorFromString(ctx, "identity with memberships must have associated resource")
		}

		associations = authorization.AppendAssociation(associations, identity.IdentityResourceID.String, &identity.IdentityResource.Name, &identity.ID, true, nil)
	}

	return associations, nil
}
