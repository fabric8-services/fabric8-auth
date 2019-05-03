package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/repository/base"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	// DefaultIDP is the name of the main authentication / identity provider
	// TODO update the value to something other than "kc" - requires db migration
	DefaultIDP = "kc"
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
	// This is the ID PK field. For identities provided by Keycloak this ID equals to the Keycloak. For other types of IDP (github, oso, etc) this ID is generated automatically
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
	IdentityResource   resource.Resource `gorm:"foreignkey:IdentityResourceID;association_foreignkey:ResourceID"`
	// Timestamp of the identity's last activity
	LastActive *time.Time
	// Timestamp of deactivation notification
	DeactivationNotification *time.Time `gorm:"column:deactivation_notification"`
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
	base.Exister
	Load(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) (*Identity, error)
	LoadWithUser(ctx context.Context, id uuid.UUID) (*Identity, error)
	Create(ctx context.Context, identity *Identity) error
	Lookup(ctx context.Context, username, profileURL, providerType string) (*Identity, error)
	Save(ctx context.Context, identity *Identity) error
	Delete(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) error
	DeleteForResource(ctx context.Context, resourceID string) error
	Query(funcs ...func(*gorm.DB) *gorm.DB) ([]Identity, error)
	List(ctx context.Context) ([]Identity, error)
	ListIdentitiesToNotifyForDeactivation(ctx context.Context, lastActivity time.Time, limit int) ([]Identity, error)
	ListIdentitiesToDeactivate(ctx context.Context, lastActivity, notification time.Time, limit int) ([]Identity, error)
	IsValid(context.Context, uuid.UUID) bool
	Search(ctx context.Context, q string, start int, limit int) ([]Identity, int, error)
	FindIdentityMemberships(ctx context.Context, identityID uuid.UUID, resourceType *string) ([]authorization.IdentityAssociation, error)
	FindIdentitiesByResourceTypeWithParentResource(ctx context.Context, resourceTypeID uuid.UUID, parentResourceID string) ([]Identity, error)
	AddMember(ctx context.Context, identityID uuid.UUID, memberID uuid.UUID) error
	RemoveMember(ctx context.Context, memberOf uuid.UUID, memberID uuid.UUID) error
	FlagPrivilegeCacheStaleForMembershipChange(ctx context.Context, memberID uuid.UUID, memberOf uuid.UUID) error
	TouchLastActive(ctx context.Context, identityID uuid.UUID) error
}

// TableName overrides the table name settings in Gorm to force a specific table name
// in the database.
func (m *GormIdentityRepository) TableName() string {
	return "identities"
}

type Membership struct {
	MemberID uuid.UUID `sql:"type:uuid" gorm:"primary_key"`
	MemberOf uuid.UUID `sql:"type:uuid" gorm:"primary_key"`
}

func (m Membership) TableName() string {
	return "membership"
}

// CRUD Functions

// Load returns a single Identity as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
// arguments funcs can be used to add conditions dynamically to current database connection
func (m *GormIdentityRepository) Load(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) (*Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "load"}, time.Now())

	var native Identity
	err := m.db.Scopes(funcs...).Table(m.TableName()).Where("id = ?", id).Find(&native).Error
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
	return base.CheckExists(ctx, m.db, m.TableName(), id)
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
	log.Debug(ctx, map[string]interface{}{
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

// Delete removes a single record. argument funcs can be used to add conditions dynamically to current database connection
func (m *GormIdentityRepository) Delete(ctx context.Context, id uuid.UUID, funcs ...func(*gorm.DB) *gorm.DB) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "delete"}, time.Now())

	obj := Identity{ID: id}
	result := m.db.Scopes(funcs...).Delete(obj)

	if result.Error != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": id,
			"err":         result.Error,
		}, "unable to delete the identity")
		return errs.WithStack(result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("identity", id.String())
	}

	log.Debug(ctx, map[string]interface{}{
		"identity_id": id,
	}, "Identity deleted!")

	return nil
}

func (m *GormIdentityRepository) DeleteForResource(ctx context.Context, resourceID string) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "deleteForResource"}, time.Now())
	err := m.db.Table(m.TableName()).Where("identity_resource_id = ?", resourceID).Delete(nil).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return errs.WithStack(err)
	}
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

// ListIdentitiesToNotifyForDeactivation return identities whose last activity is older than the given one. The result size is limited to the given
// number of identities (ordered by last activity)
// if limit is a negative value (eg: '-1'), it is ignored
func (m *GormIdentityRepository) ListIdentitiesToNotifyForDeactivation(ctx context.Context, lastActivity time.Time, limit int) ([]Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "user", "listIdentitiesToNotifyForDeactivation"}, time.Now())
	var identities []Identity
	// sort identities by most inactive and then by date of creation to make sure we always get the same sublist of identities between
	// queries to notify before deactivation and queries to deactivate for real.
	err := m.db.Model(&Identity{}).Preload("User").
		Where(`last_active < ? AND deactivation_notification IS NULL`, lastActivity).
		Joins("left join users on identities.user_id = users.id").Where("users.banned is false").
		Order("last_active, created_at").
		Limit(limit).Find(&identities).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"identities_to_notify_before_deactivation": len(identities),
	}, "listing identities to notify before deactivation completed")

	return identities, nil
}

// ListIdentitiesToDeactivate return identities whose last activity is older than the given one,
// and for whom there is a `deactivation_notification` value and who were not previously banned.
// The result size is limited to the given number of identities (ordered by last activity)
// if limit is a negative value (eg: '-1'), it is ignored
func (m *GormIdentityRepository) ListIdentitiesToDeactivate(ctx context.Context, lastActivity, notification time.Time, limit int) ([]Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "user", "listIdentitiesToDeactivate"}, time.Now())
	var identities []Identity
	// sort identities by most inactive and then by date of creation to make sure we always get the same sublist of identities between
	// queries to notify before deactivation and queries to deactivate for real.
	err := m.db.Model(&Identity{}).
		Where("last_active < ? and deactivation_notification < ?", lastActivity, notification).
		Joins("left join users on identities.user_id = users.id").Where("users.banned is false").
		Order("last_active, created_at").Limit(limit).Find(&identities).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, errs.WithStack(err)
	}
	log.Info(ctx, map[string]interface{}{
		"inactive_since":           lastActivity.Format("2006-01-02 15:04:05"),
		"notified_before":          notification.Format("2006-01-02 15:04:05"),
		"identities_to_deactivate": len(identities),
	}, "Listing identities to deactivate completed")

	return identities, nil
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
  AND identities.deleted_at IS NULL
  AND users.banned IS false
  AND users.deleted_at IS NULL
UNION SELECT
  identities.id AS identity_id,
  identities.username,
  users.*
FROM
  identities, users
WHERE  
  identities.user_id = users.id 
  AND identities.deleted_at IS NULL
  AND users.deleted_at IS NULL
  AND users.banned IS false 
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
	defer goa.MeasureSince([]string{"goa", "db", "identity", "FindIdentityMemberships"}, time.Now())
	associations := []authorization.IdentityAssociation{}

	var identities []Identity

	// query for identities in which the user is a member
	q := m.db.Table(m.TableName()).Preload("IdentityResource").Preload("IdentityResource.ParentResource")

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

	for _, identity := range identities {
		// TODO for some reason gorm's nested preloads aren't working here, some time should be spent in the gorm source code to find out why,
		// after which we should be able to remove this code
		if identity.IdentityResource.ParentResourceID != nil && identity.IdentityResource.ParentResource == nil {

			var native resource.Resource
			err = m.db.Table("resource").Where("resource_id = ?", identity.IdentityResource.ParentResourceID).Find(&native).Error
			if err != nil {
				return nil, err
			}
			identity.IdentityResource.ParentResource = &native
		}

		associations = authorization.AppendAssociation(associations, identity.IdentityResourceID.String, &identity.IdentityResource.Name, identity.IdentityResource.ParentResourceID, &identity.ID, true, nil)
	}

	return associations, nil
}

// FindIdentitiesWithParentResource returns an array of Identity objects for which their corresponding resource is a child of the specified parent resource
func (m *GormIdentityRepository) FindIdentitiesByResourceTypeWithParentResource(ctx context.Context, resourceTypeID uuid.UUID, parentResourceID string) ([]Identity, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "FindIdentitiesByResourceTypeWithParentResource"}, time.Now())

	var identities []Identity

	err := m.db.Table(m.TableName()).Preload("IdentityResource").
		Joins("JOIN resource r ON r.resource_id = identities.identity_resource_id AND r.resource_type_id = ? AND r.parent_resource_id = ?", resourceTypeID, parentResourceID).
		Find(&identities).Error

	if err != nil {
		return nil, err
	}

	return identities, nil
}

func (m *GormIdentityRepository) AddMember(ctx context.Context, identityID uuid.UUID, memberID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "AddMember"}, time.Now())

	var identity Identity
	err := m.db.Table(m.TableName()).Preload("IdentityResource").Preload("IdentityResource.ResourceType").Where("id = ?", identityID).Find(&identity).Error
	if err == gorm.ErrRecordNotFound {
		return errs.WithStack(errors.NewNotFoundError("identity", identityID.String()))
	}

	if !identity.IdentityResourceID.Valid {
		return errs.WithStack(errors.NewBadParameterErrorFromString("identityID", identityID.String(), "Specified identity has no corresponding resource"))
	}

	if !authorization.CanHaveMembers(identity.IdentityResource.ResourceType.Name) {
		return errs.WithStack(errors.NewBadParameterErrorFromString("identityID", identityID.String(), "Specified identity may not have members"))
	}

	var member Identity
	err = m.db.Table(m.TableName()).Where("id = ?", memberID).Find(&member).Error
	if err == gorm.ErrRecordNotFound {
		return errs.WithStack(errors.NewNotFoundError("identity", memberID.String()))
	}

	membership := &Membership{
		MemberOf: identityID,
		MemberID: memberID,
	}

	err = m.db.Create(membership).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"member_of": identityID,
			"member_id": memberID,
			"err":       err,
		}, "unable to create the membership")
		return errs.WithStack(err)
	}

	err = m.FlagPrivilegeCacheStaleForMembershipChange(ctx, identityID, memberID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"member_of": identityID,
			"member_id": memberID,
			"err":       err,
		}, "unable to create the membership - error notifying privilege cache")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"member_of": identityID,
		"member_id": memberID,
	}, "Membership created!")

	return nil
}

// RemoveMember removes an existing membership with the specified memberOf and memberID values
func (m *GormIdentityRepository) RemoveMember(ctx context.Context, memberOf uuid.UUID, memberID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "RemoveMember"}, time.Now())

	membership := &Membership{
		MemberOf: memberOf,
		MemberID: memberID,
	}

	err := m.db.Delete(membership).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"member_of": memberOf,
			"member_id": memberID,
			"err":       err,
		}, "unable to remove the membership")
		return errs.WithStack(err)
	}

	err = m.FlagPrivilegeCacheStaleForMembershipChange(ctx, memberID, memberOf)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"member_of": memberOf,
			"member_id": memberID,
			"err":       err,
		}, "unable to remove the membership - error notifying privilege cache")
		return errs.WithStack(err)
	}

	log.Info(ctx, map[string]interface{}{
		"member_of": memberOf,
		"member_id": memberID,
	}, "Membership removed!")

	return nil
}

// FlagStaleForMembershipChange executes two update queries; the first sets the stale flag to true for all privilege
// cache records where the identity ID is equal to, or a descendent of (via memberships) the specified member ID, and
// the resourceID is contained in a set of resources for which there is an IDENTITY_ROLE record for the resource, or
// any of its descendent resources, and the IDENTITY_ROLE's identity is in the identity ancestor hierarchy specified by
// the memberOf parameter.
//
// The second query updates the token table, setting the STALE flag of the token STATUS field to true, for all
// token records that are mapped to the corresponding privilege cache records in the first query, via the
// many-to-many TOKEN_PRIVILEGE table
func (m *GormIdentityRepository) FlagPrivilegeCacheStaleForMembershipChange(ctx context.Context, memberID uuid.UUID, memberOf uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "FlagPrivilegeCacheStaleForMembershipChange"}, time.Now())

	result := m.db.Exec(`WITH member_identity_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    member_id
	  FROM
	    membership
	  WHERE
	    member_of = ? /* MEMBER_ID */
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
	    id = ? /* MEMBER_ID */
),
member_of_identity_hierarchy AS (
WITH RECURSIVE m AS (
  SELECT
    member_of
  FROM
    membership
  WHERE
    member_id = ? /* MEMBER_OF */
  UNION SELECT
    p.member_of
  FROM
    membership p INNER JOIN m ON m.member_of = p.member_id
  )
  SELECT
    member_of AS identity_id
  FROM 
    m
  UNION SELECT
    id
  FROM
    identities
  WHERE
    id = ? /* MEMBER_OF */
),
resource_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    resource_id, parent_resource_id
	  FROM
	    resource
	  WHERE
        deleted_at IS NULL
	    AND resource_id IN (
          SELECT 
            resource_id 
          FROM 
            identity_role ir 
          WHERE 
            ir.deleted_at IS NULL 
            AND ir.identity_id IN (SELECT identity_id FROM member_of_identity_hierarchy)
        )
	  UNION SELECT
	    p.resource_id, p.parent_resource_id
	  FROM
	    resource p INNER JOIN m ON m.resource_id = p.parent_resource_id
      WHERE
        p.deleted_at IS NULL
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
  AND identity_id IN (SELECT identity_id FROM member_identity_hierarchy)
  AND deleted_at IS NULL
  `, memberID, memberID, memberOf, memberOf)

	if result.Error != nil {
		return errors.NewInternalError(ctx, result.Error)
	}

	result = m.db.Exec(`WITH member_identity_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    member_id
	  FROM
	    membership
	  WHERE
	    member_of = ? /* MEMBER_ID */
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
	    id = ? /* MEMBER_ID */
),
member_of_identity_hierarchy AS (
WITH RECURSIVE m AS (
  SELECT
    member_of
  FROM
    membership
  WHERE
    member_id = ? /* MEMBER_OF */
  UNION SELECT
    p.member_of
  FROM
    membership p INNER JOIN m ON m.member_of = p.member_id
  )
  SELECT
    member_of AS identity_id
  FROM 
    m
  UNION SELECT
    id
  FROM
    identities
  WHERE
    id = ? /* MEMBER_OF */
),
resource_hierarchy AS (
	WITH RECURSIVE m AS (
	  SELECT
	    resource_id, parent_resource_id
	  FROM
	    resource
	  WHERE
        deleted_at IS NULL
	    AND resource_id IN (
          SELECT 
            resource_id 
          FROM 
            identity_role ir 
          WHERE 
            ir.deleted_at IS NULL 
            AND ir.identity_id IN (SELECT identity_id FROM member_of_identity_hierarchy)
        )
	  UNION SELECT
	    p.resource_id, p.parent_resource_id
	  FROM
	    resource p INNER JOIN m ON m.resource_id = p.parent_resource_id
      WHERE
        p.deleted_at IS NULL
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
  AND pc.identity_id IN (SELECT identity_id FROM member_identity_hierarchy)
  AND pc.deleted_at IS NULL
  `, memberID, memberID, memberOf, memberOf, token.TOKEN_STATUS_STALE)

	if result.Error != nil {
		return errors.NewInternalError(ctx, result.Error)
	}

	log.Debug(ctx, map[string]interface{}{
		"rows_marked_stale": result.RowsAffected,
	}, "Privilege cache rows marked stale")

	return nil
}

// TouchLastActive is intended to be a lightweight method that updates the last active column for a specified identity
// to the current timestamp. Also, it resets the `deactivation_notification` timestamp so we can send another deactivation
// notification to the user if she is once again inactive in the future.
func (m *GormIdentityRepository) TouchLastActive(ctx context.Context, identityID uuid.UUID) error {
	defer goa.MeasureSince([]string{"goa", "db", "identity", "TouchLastActive"}, time.Now())

	err := m.db.Exec("UPDATE identities SET last_active = ?, deactivation_notification = NULL WHERE id = ?", time.Now(), identityID).Error
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"id":  identityID,
			"err": err,
		}, "unable to update last active time")
		return errs.WithStack(err)
	}
	log.Debug(ctx, map[string]interface{}{
		"id": identityID,
	}, "updated last active time")

	return nil
}
