package account_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type identityBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo account.IdentityRepository
}

func TestRunIdentityBlackBoxTest(t *testing.T) {
	suite.Run(t, &identityBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *identityBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = account.NewIdentityRepository(s.DB)
}

func (s *identityBlackBoxTest) TestOKToDelete() {
	// given
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "someuserTestIdentity",
		ProviderType: account.KeycloakIDP}

	identity2 := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "onemoreuserTestIdentity",
		ProviderType: account.KeycloakIDP}

	err := s.repo.Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")
	err = s.repo.Create(s.Ctx, identity2)
	require.Nil(s.T(), err, "Could not create identity")
	// when
	err = s.repo.Delete(s.Ctx, identity.ID)
	// then
	assert.Nil(s.T(), err)
	identities, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list identities")
	require.True(s.T(), len(identities) > 0)
	for _, ident := range identities {
		require.NotEqual(s.T(), "someuserTestIdentity", ident.Username)
	}
}

func (s *identityBlackBoxTest) TestOKToLoad() {
	createAndLoad(s)
}

func (s *identityBlackBoxTest) TestExistsIdentity() {
	t := s.T()
	resource.Require(t, resource.Database)

	t.Run("identity exists", func(t *testing.T) {
		//t.Parallel()
		// given
		identity := createAndLoad(s)
		// when
		err := s.repo.CheckExists(s.Ctx, identity.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("identity doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *identityBlackBoxTest) TestOKToSave() {
	// given
	identity := createAndLoad(s)
	// when
	identity.Username = "newusernameTestIdentity"
	err := s.repo.Save(s.Ctx, identity)
	// then
	require.Nil(s.T(), err, "Could not update identity")
}

func (s *identityBlackBoxTest) TestLoadIdentityAndUserFailsIfUserOrIdentityDoNotExist() {
	// Identity exists but not assosiated with any user
	identity := createAndLoad(s)
	_, err := s.repo.LoadWithUser(s.Ctx, identity.ID)
	require.NotNil(s.T(), err)

	assert.Equal(s.T(), errors.NewNotFoundError("user for identity", identity.ID.String()).Error(), err.Error())

	// Identity does not exist
	id := uuid.NewV4()
	_, err = s.repo.LoadWithUser(s.Ctx, id)
	require.NotNil(s.T(), err)
	assert.Equal(s.T(), errors.NewNotFoundError("identity", id.String()).Error(), err.Error())
}

func (s *identityBlackBoxTest) TestLoadIdentityAndUserOK() {
	// Create test user & identity
	testUser := &account.User{
		ID:       uuid.NewV4(),
		Email:    uuid.NewV4().String(),
		FullName: "TestLoadIdentityAndUserOK Developer",
		Cluster:  "https://api.starter-us-east-2a.openshift.com",
	}
	testIdentity := &account.Identity{
		Username:     "TestLoadIdentityAndUserOK" + uuid.NewV4().String(),
		ProviderType: account.KeycloakIDP,
		User:         *testUser,
	}
	userRepository := account.NewUserRepository(s.DB)
	userRepository.Create(s.Ctx, testUser)
	s.repo.Create(s.Ctx, testIdentity)

	// Check load
	identity, err := s.repo.LoadWithUser(s.Ctx, testIdentity.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identity)
	testIdentity.CreatedAt = identity.CreatedAt // Align timestamps
	testIdentity.UpdatedAt = identity.UpdatedAt
	testIdentity.Lifecycle = identity.Lifecycle
	testIdentity.User.UpdatedAt = identity.User.UpdatedAt
	testIdentity.User.CreatedAt = identity.User.CreatedAt
	testIdentity.User.Lifecycle = identity.User.Lifecycle
	assert.Equal(s.T(), testIdentity, identity)
}

func createAndLoad(s *identityBlackBoxTest) *account.Identity {
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "someuserTestIdentity2",
		ProviderType: account.KeycloakIDP}

	err := s.repo.Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")
	// when
	idnt, err := s.repo.Load(s.Ctx, identity.ID)
	// then
	require.Nil(s.T(), err, "Could not load identity")
	require.Equal(s.T(), "someuserTestIdentity2", idnt.Username)
	return idnt
}
