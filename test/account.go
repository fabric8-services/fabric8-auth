package test

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/models"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// TestUser only creates in memory obj for testing purposes
var TestUser = account.User{
	ID:       uuid.NewV4(),
	Email:    "testdeveloper@testalm.io",
	FullName: "Test Developer",
	Cluster:  "Test Cluster",
}

// TestUser2 only creates in memory obj for testing purposes.
// This TestUser2 can be used to verify that some entity created by TestUser
// can be later updated or deleted (or not) by another user.
var TestUser2 = account.User{
	ID:       uuid.NewV4(),
	Email:    "testdeveloper2@testalm.io",
	FullName: "Test Developer 2",
}

// TestUser only creates in memory obj for testing purposes
var TestUser3 = account.User{
	ID:       uuid.NewV4(),
	Email:    uuid.NewV4().String(),
	FullName: "Test Developer",
	Cluster:  "Test Cluster",
}

// TestIdentity only creates in memory obj for testing purposes
var TestIdentity = account.Identity{
	ID:       uuid.NewV4(),
	Username: "TestDeveloper",
	User:     TestUser,
}

// TestObserverIdentity only creates in memory obj for testing purposes
var TestObserverIdentity = account.Identity{
	ID:       uuid.NewV4(),
	Username: "TestObserver",
	User:     TestUser,
}

// TestIdentity2 only creates in memory obj for testing purposes
var TestIdentity2 = account.Identity{
	ID:       uuid.NewV4(),
	Username: "TestDeveloper2",
	User:     TestUser2,
}

var TestOnlineRegistrationAppIdentity = account.Identity{
	ID:       uuid.NewV4(),
	Username: "online-registration",
	User:     TestUser,
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
	testIdentity := account.Identity{
		Username:     username,
		ProviderType: providerType,
		User:         TestUser3,
	}
	err := CreateTestIdentityAndUserInDB(db, &testIdentity)
	return testIdentity, err
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

	err := models.Transactional(db, func(tx *gorm.DB) error {
		return userRepository.Create(context.Background(), &identity.User)
	})
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"err":      err,
			"identity": identity.User,
		}, "unable to create user")
		return err
	}
	log.Info(nil, map[string]interface{}{"user_id": identity.User.ID}, "created user")

	err = models.Transactional(db, func(tx *gorm.DB) error {
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
