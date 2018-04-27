package test

import (
	"context"

	"database/sql"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resourceRepo "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourceTypeRepo "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/models"
	"github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

// TestUser only creates in memory obj for testing purposes
var TestUser = account.User{
	ID:       uuid.Must(uuid.NewV4()),
	Email:    "testdeveloper@testalm.io" + uuid.Must(uuid.NewV4()).String(),
	FullName: "Test Developer",
	Cluster:  "https://api.starter-us-east-2.openshift.com",
}

// TestUser2 only creates in memory obj for testing purposes.
// This TestUser2 can be used to verify that some entity created by TestUser
// can be later updated or deleted (or not) by another user.
var TestUser2 = account.User{
	ID:       uuid.Must(uuid.NewV4()),
	Email:    "testdeveloper2@testalm.io" + uuid.Must(uuid.NewV4()).String(),
	FullName: "Test Developer 2",
	Cluster:  "https://api.starter-us-east-2.openshift.com",
}

// TestUser only creates in memory obj for testing purposes
var TestUser3 = account.User{
	ID:       uuid.Must(uuid.NewV4()),
	Email:    uuid.Must(uuid.NewV4()).String(),
	FullName: "Test Developer",
	Cluster:  "https://api.starter-us-east-2.openshift.com",
}

// TestUserPrivate only creates in memory obj for testing purposes
var TestUserPrivate = account.User{
	ID:           uuid.Must(uuid.NewV4()),
	Email:        uuid.Must(uuid.NewV4()).String(),
	FullName:     "Test Developer",
	Cluster:      "https://api.starter-us-east-2.openshift.com",
	EmailPrivate: true,
}

// TestIdentity only creates in memory obj for testing purposes
var TestIdentity = account.Identity{
	ID:           uuid.Must(uuid.NewV4()),
	Username:     "TestDeveloper" + uuid.Must(uuid.NewV4()).String(),
	User:         TestUser,
	ProviderType: account.KeycloakIDP,
}

// TestObserverIdentity only creates in memory obj for testing purposes
var TestObserverIdentity = account.Identity{
	ID:       uuid.Must(uuid.NewV4()),
	Username: "TestObserver",
	User:     TestUser,
}

// TestIdentity2 only creates in memory obj for testing purposes
var TestIdentity2 = account.Identity{
	ID:           uuid.Must(uuid.NewV4()),
	Username:     "TestDeveloper2" + uuid.Must(uuid.NewV4()).String(),
	User:         TestUser2,
	ProviderType: account.KeycloakIDP,
}

var TestOnlineRegistrationAppIdentity = account.Identity{
	ID:       uuid.Must(uuid.NewV4()),
	Username: "online-registration",
	User:     TestUser,
}

var TestNotificationIdentity = account.Identity{
	ID:       uuid.Must(uuid.NewV4()),
	Username: "fabric8-notification",
	User:     TestUser,
}

var TestTenantIdentity = account.Identity{
	ID:       uuid.Must(uuid.NewV4()),
	Username: "fabric8-tenant",
	User:     TestUser,
}

// CreateLonelyTestIdentity creates an identity not associated with any user. For testing purpose only.
func CreateLonelyTestIdentity(db *gorm.DB, username string) (account.Identity, error) {
	testIdentity := account.Identity{
		Username:     username,
		ProviderType: "testProvider",
	}
	err := CreateTestIdentityForAccountIdentity(db, &testIdentity)
	return testIdentity, err
}

// CreateTestOrganizationIdentity creates an identity/resource pair in the database. For testing purposes only.
func CreateTestOrganizationIdentity(db *gorm.DB) (account.Identity, error) {
	var orgIdentity account.Identity

	repo := resourceRepo.NewResourceRepository(db)
	resourceTypeRepo := resourceTypeRepo.NewResourceTypeRepository(db)

	err := models.Transactional(db, func(tx *gorm.DB) error {
		resourceType, err := resourceTypeRepo.Lookup(context.Background(), authorization.IdentityResourceTypeOrganization)

		if err != nil {
			return err
		}

		orgResource := resourceRepo.Resource{
			Name:           "test-organization",
			ResourceTypeID: resourceType.ResourceTypeID,
		}

		err = repo.Create(context.Background(), &orgResource)

		if err != nil {
			return err
		}

		orgIdentity = account.Identity{
			IdentityResourceID: sql.NullString{orgResource.ResourceID, true},
		}

		err = CreateTestIdentityForAccountIdentity(db, &orgIdentity)
		return err
	})

	return orgIdentity, err
}

// CreateTestIdentity creates an identity with the given `username` in the database. For testing purpose only.
func CreateTestIdentity(db *gorm.DB, username, providerType string) (account.Identity, error) {
	testIdentity := account.Identity{
		Username:     username,
		ProviderType: providerType,
		User:         TestUser3,
	}
	err := CreateTestIdentityForAccountIdentity(db, &testIdentity)
	return testIdentity, err
}

// CreateTestIdentityAndUser creates an identity & user with the given `username` in the database. For testing purpose only.
func CreateTestIdentityAndUser(db *gorm.DB, username, providerType string) (account.Identity, error) {
	testUser := account.User{
		ID:       uuid.Must(uuid.NewV4()),
		Email:    uuid.Must(uuid.NewV4()).String(),
		FullName: "Test Developer",
		Cluster:  "https://api.starter-us-east-2a.openshift.com",
	}
	testIdentity := account.Identity{
		Username:     username,
		ProviderType: providerType,
		User:         testUser,
	}
	err := CreateTestIdentityAndUserInDB(db, &testIdentity)
	return testIdentity, err
}

func CreateDeprovisionedTestIdentityAndUser(db *gorm.DB, username string) (account.Identity, error) {
	testUser := account.User{
		ID:            uuid.Must(uuid.NewV4()),
		Email:         uuid.Must(uuid.NewV4()).String(),
		FullName:      "Test Developer " + username,
		Cluster:       "https://api.starter-us-east-2a.openshift.com",
		Deprovisioned: true,
	}
	testIdentity := account.Identity{
		Username:     username,
		ProviderType: account.KeycloakIDP,
		User:         testUser,
	}
	err := CreateTestIdentityAndUserInDB(db, &testIdentity)
	return testIdentity, err
}

// CreateTestIdentityAndUserWithDefaultProviderType creates an identity & user with the given `username` in the database. For testing purpose only.
func CreateTestIdentityAndUserWithDefaultProviderType(db *gorm.DB, username string) (account.Identity, error) {
	return CreateTestIdentityAndUser(db, username, account.KeycloakIDP)
}

// EmbedTestIdentityTokenInContext creates an identity & user with the given `username` in the database.
// Generates a token for that identity and embed the token in the context.
func EmbedTestIdentityTokenInContext(db *gorm.DB, username string) (account.Identity, context.Context, error) {
	// Create a Sample user and identity
	identity, err := CreateTestIdentityAndUserWithDefaultProviderType(db, username)
	if err != nil {
		return identity, nil, err
	}

	// Embed Token in the context
	ctx, err := token.EmbedTokenInContext(identity.ID.String(), identity.Username)

	return identity, ctx, err
}

// CreateTestUser creates a new user from a given user object
func CreateTestUser(db *gorm.DB, user *account.User) (account.Identity, error) {
	userRepository := account.NewUserRepository(db)
	identityRepository := account.NewIdentityRepository(db)
	identity := account.Identity{
		Username:     uuid.Must(uuid.NewV4()).String(),
		ProviderType: account.KeycloakIDP,
	}
	err := models.Transactional(db, func(tx *gorm.DB) error {
		err := userRepository.Create(context.Background(), user)
		if err != nil {
			return err
		}
		identity.User = *user
		identity.UserID.UUID = user.ID
		return identityRepository.Create(context.Background(), &identity)
	})
	return identity, err
}

// CreateTestIdentityForAccountIdentity creates an account.Identity in the database. For testing purpose only.
// This function unlike CreateTestIdentity() allows to create an Identity with pre-defined ID.
func CreateTestIdentityForAccountIdentity(db *gorm.DB, identity *account.Identity) error {

	identityRepository := account.NewIdentityRepository(db)

	err := models.Transactional(db, func(tx *gorm.DB) error {
		return identityRepository.Create(context.Background(), identity)
	})
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"err":      err,
			"identity": identity,
		}, "unable to create identity")
	} else {
		log.Info(nil, map[string]interface{}{"identity_id": identity.ID}, "created identity")
	}
	return err
}

// CreateTestIdentityAndUserInDB creates an account.Identity and account.User
// in the database. For testing purpose only. Not re-using CreateTestIdentityForAccountIdentity
// because it is used in many places and will cause errors/failures.
// This function unlike CreateTestIdentity() allows to create an Identity with pre-defined ID.
func CreateTestIdentityAndUserInDB(db *gorm.DB, identity *account.Identity) error {

	identityRepository := account.NewIdentityRepository(db)
	userRepository := account.NewUserRepository(db)

	transactionError := models.Transactional(db, func(tx *gorm.DB) error {
		err := userRepository.Create(context.Background(), &identity.User)

		if err != nil {
			log.Error(nil, map[string]interface{}{
				"err":      err,
				"identity": identity.User,
			}, "unable to create user")
			return err
		}
		log.Info(nil, map[string]interface{}{"user_id": identity.User.ID}, "created user")

		err = identityRepository.Create(context.Background(), identity)

		if err != nil {
			log.Error(nil, map[string]interface{}{
				"err":      err,
				"identity": identity,
			}, "unable to create identity")
		} else {
			log.Info(nil, map[string]interface{}{"identity_id": identity.ID}, "created identity")
		}
		return err
	})
	return transactionError
}
