package repository_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type userBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo repository.UserRepository
}

func TestRunUserBlackBoxTest(t *testing.T) {
	suite.Run(t, &userBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *userBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = repository.NewUserRepository(s.DB)
}

func (s *userBlackBoxTest) TestOKToDelete() {
	s.T().Run("ok by user ID", func(t *testing.T) {
		// create 2 users, where the first one would be deleted.
		user := createAndLoadUser(s, false)
		createAndLoadUser(s, false)

		err := s.repo.Delete(s.Ctx, user.ID)
		assert.Nil(t, err)

		// lets see how many are present.
		users, err := s.repo.List(s.Ctx)
		require.Nil(t, err, "Could not list users")
		require.True(t, len(users) > 0)

		for _, data := range users {
			// The user 'user' was deleted and rest were not deleted, hence we check
			// that none of the user objects returned include the one deleted.
			require.NotEqual(t, user.ID.String(), data.ID.String())
		}
	})
}

func (s *userBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "user with id '%s' not found", id.String())
}

func (s *userBlackBoxTest) TestOKToLoad() {
	createAndLoadUser(s, false) // this function does the needful already
}

func (s *userBlackBoxTest) TestOKToLoadByDynamicCondition() {
	// create 2 users, where the first one would be deleted.
	user := createAndLoadUser(s, false)
	createAndLoadUser(s, false)

	// soft delete user
	err := s.repo.Delete(s.Ctx, user.ID)
	require.Nil(s.T(), err)

	// load softly deleted user.
	loadedUser, err := s.repo.Load(s.Ctx, user.ID, func(db *gorm.DB) *gorm.DB {
		return db.Unscoped()
	})
	require.Nil(s.T(), err, "Could not load user")
	assert.NotNil(s.T(), loadedUser.DeletedAt)
	assert.Equal(s.T(), user.ID, loadedUser.ID)
}

func (s *userBlackBoxTest) TestExistsUser() {
	t := s.T()

	t.Run("user exists", func(t *testing.T) {
		//t.Parallel()
		user := createAndLoadUser(s, false)
		// when
		err := s.repo.CheckExists(s.Ctx, user.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("user doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (s *userBlackBoxTest) TestOKToSave() {
	user := createAndLoadUser(s, false)

	user.FullName = "newusernameTestUser"
	user.Cluster = "NewCluster" + uuid.NewV4().String()
	err := s.repo.Save(s.Ctx, user)
	require.Nil(s.T(), err, "Could not update user")

	updatedUser, err := s.repo.Load(s.Ctx, user.ID)
	require.Nil(s.T(), err, "Could not load user")
	assert.Equal(s.T(), user.FullName, updatedUser.FullName)
	assert.Equal(s.T(), user.Cluster, updatedUser.Cluster)
	fields := user.ContextInformation
	assert.Equal(s.T(), fields["last_visited"], "http://www.google.com")
	assert.Equal(s.T(), fields["myid"], "71f343e3-2bfa-4ec6-86d4-79b91476acfc")

}

func (s *userBlackBoxTest) TestCreateUserWithoutClusterFails() {
	t := s.T()
	user := &repository.User{
		ID:       uuid.NewV4(),
		Email:    "noclustersomeuser@TestUser" + uuid.NewV4().String(),
		FullName: "someuserTestUser" + uuid.NewV4().String(),
		ImageURL: "someImageUrl" + uuid.NewV4().String(),
		Bio:      "somebio" + uuid.NewV4().String(),
		URL:      "someurl" + uuid.NewV4().String(),
		ContextInformation: account.ContextInformation{
			"space":        uuid.NewV4(),
			"last_visited": "http://www.google.com",
			"myid":         "71f343e3-2bfa-4ec6-86d4-79b91476acfc",
		},
	}
	err := s.repo.Create(s.Ctx, user)
	// No cluster set. Should fail.
	require.NotNil(t, err)

	user.Cluster = "someClusterForTest"
	err = s.repo.Create(s.Ctx, user)
	// Cluster is set now. Should be OK.
	require.Nil(t, err)
}

func (s *userBlackBoxTest) TestUpdateUserWithoutClusterFails() {
	t := s.T()
	user := createAndLoadUser(s, false)

	// If we try to set an empty cluster for an existing user it should fail.
	err := s.DB.Exec(fmt.Sprintf("update users set cluster = '' where id = '%s'", user.ID.String())).Error
	require.NotNil(t, err)

	err = s.DB.Exec(fmt.Sprintf("update users set cluster = NULL where id = '%s'", user.ID.String())).Error
	require.NotNil(t, err)

	// Check that Save(user) doesn't update the cluster if it's empty
	// TODO we should switch to db.Save(&user) instead of db.Model(&user).Updates(model) in userRepo.Save(user). Otherwise we can't really set empty values to User's fields
	require.NotEmpty(t, user.Cluster)
	user.Cluster = ""
	err = s.repo.Save(s.Ctx, user)
	require.NotNil(t, err)
	u, err := s.repo.Load(s.Ctx, user.ID)
	require.Nil(t, err)
	require.NotEmpty(t, u.Cluster)

	// OK. Let's now try with setting a not empty cluster. Should pass this time.
	user.Cluster = "someClusterForTest"
	err = s.repo.Save(s.Ctx, user)
	require.Nil(t, err)
}

func (s *userBlackBoxTest) TestUpdateToEmptyString() {
	t := s.T()
	user := createAndLoadUser(s, false)

	err := s.repo.Save(s.Ctx, user)
	require.Nil(t, err)
	user.Bio = ""
	err = s.repo.Save(s.Ctx, user)
	require.Nil(t, err)
	u, err := s.repo.Load(s.Ctx, user.ID)
	require.Nil(t, err)
	require.Empty(t, u.Bio)
}

func (s *userBlackBoxTest) TestEmailFilters() {
	userWithPublicEmail := createAndLoadUser(s, false)
	createAndLoadUser(s, false)
	userWithPrivateEmail := createAndLoadUser(s, true)
	createAndLoadUser(s, true)

	// Filter users by email

	users, err := s.repo.Query(repository.UserFilterByEmail(userWithPublicEmail.Email))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 1)
	require.Equal(s.T(), userWithPublicEmail.Email, users[0].Email)

	users, err = s.repo.Query(repository.UserFilterByEmail(userWithPrivateEmail.Email))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 1)
	require.Equal(s.T(), userWithPrivateEmail.Email, users[0].Email)

	// Filter users by email privacy

	s.checkPrivateEmailFilter(false, userWithPublicEmail.Email)
	s.checkPrivateEmailFilter(true, userWithPrivateEmail.Email)

	// Filter users by email and email privacy

	// Search for a public email and the give email is public. User is found
	users, err = s.repo.Query(repository.UserFilterByEmail(userWithPublicEmail.Email), repository.UserFilterByEmailPrivacy(false))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 1)
	require.Equal(s.T(), userWithPublicEmail.Email, users[0].Email)

	// Search for a public email but the give email is private. User is not found
	users, err = s.repo.Query(repository.UserFilterByEmail(userWithPrivateEmail.Email), repository.UserFilterByEmailPrivacy(false))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 0)

	// Search for a private email and the give email is private. User is found
	users, err = s.repo.Query(repository.UserFilterByEmail(userWithPrivateEmail.Email), repository.UserFilterByEmailPrivacy(true))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 1)
	require.Equal(s.T(), userWithPrivateEmail.Email, users[0].Email)

	// Search for a private email but the give email is public. User is not found
	users, err = s.repo.Query(repository.UserFilterByEmail(userWithPublicEmail.Email), repository.UserFilterByEmailPrivacy(true))
	require.NoError(s.T(), err)
	require.Len(s.T(), users, 0)
}

func (s *userBlackBoxTest) checkPrivateEmailFilter(privateEmails bool, expectedEmail string) {
	users, err := s.repo.Query(repository.UserFilterByEmailPrivacy(privateEmails))
	require.NoError(s.T(), err)
	require.True(s.T(), len(users) > 0)
	var found bool
	for _, user := range users {
		if user.Email == expectedEmail {
			found = true
			break
		}
	}
	require.True(s.T(), found)
}

func createAndLoadUser(s *userBlackBoxTest, emailPrivate bool) *repository.User {
	user := &repository.User{
		ID:           uuid.NewV4(),
		Email:        "someuser@TestUser" + uuid.NewV4().String(),
		EmailPrivate: emailPrivate,
		FullName:     "someuserTestUser" + uuid.NewV4().String(),
		ImageURL:     "someImageUrl" + uuid.NewV4().String(),
		Bio:          "somebio" + uuid.NewV4().String(),
		URL:          "someurl" + uuid.NewV4().String(),
		Cluster:      "somecluster" + uuid.NewV4().String(),
		ContextInformation: account.ContextInformation{
			"space":        uuid.NewV4(),
			"last_visited": "http://www.google.com",
			"myid":         "71f343e3-2bfa-4ec6-86d4-79b91476acfc",
		},
	}

	err := s.repo.Create(s.Ctx, user)
	require.Nil(s.T(), err, "Could not create user")

	createdUser, err := s.repo.Load(s.Ctx, user.ID)
	require.Nil(s.T(), err, "Could not load user")
	require.Equal(s.T(), user.Email, createdUser.Email)
	require.Equal(s.T(), user.ID, createdUser.ID)
	require.Equal(s.T(), user.ContextInformation["last_visited"], createdUser.ContextInformation["last_visited"])

	return createdUser
}
