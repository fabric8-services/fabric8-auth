package account_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type identityBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunIdentityBlackBoxTest(t *testing.T) {
	suite.Run(t, &identityBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *identityBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
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

	err := s.Application.Identities().Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")
	err = s.Application.Identities().Create(s.Ctx, identity2)
	require.Nil(s.T(), err, "Could not create identity")
	// when
	err = s.Application.Identities().Delete(s.Ctx, identity.ID)
	// then
	assert.Nil(s.T(), err)
	identities, err := s.Application.Identities().List(s.Ctx)
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
		err := s.Application.Identities().CheckExists(s.Ctx, identity.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("identity doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.Application.Identities().CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (s *identityBlackBoxTest) TestOKToSave() {
	// given
	identity := createAndLoad(s)
	// when
	identity.Username = "newusernameTestIdentity"
	err := s.Application.Identities().Save(s.Ctx, identity)
	// then
	require.Nil(s.T(), err, "Could not update identity")
}

func (s *identityBlackBoxTest) TestLoadIdentityAndUserFailsIfUserOrIdentityDoNotExist() {
	// Identity exists but not associated with any user
	identity := createAndLoad(s)
	_, err := s.Application.Identities().LoadWithUser(s.Ctx, identity.ID)
	require.NotNil(s.T(), err)

	assert.Equal(s.T(), errors.NewNotFoundError("user for identity", identity.ID.String()).Error(), err.Error())

	// Identity does not exist
	id := uuid.NewV4()
	_, err = s.Application.Identities().LoadWithUser(s.Ctx, id)
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
	s.Application.Identities().Create(s.Ctx, testIdentity)

	// Check load
	identity, err := s.Application.Identities().LoadWithUser(s.Ctx, testIdentity.ID)
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

func (s *identityBlackBoxTest) TestUserIdentityIsUser() {
	// Create test user & identity
	testUser := &account.User{
		ID:       uuid.NewV4(),
		Email:    uuid.NewV4().String(),
		FullName: "TestUserIdentityIsUser Developer",
		Cluster:  "https://api.starter-us-east-2a.openshift.com",
	}
	testIdentity := &account.Identity{
		Username:     "TestUserIdentityIsUser" + uuid.NewV4().String(),
		ProviderType: account.KeycloakIDP,
		User:         *testUser,
	}
	userRepository := account.NewUserRepository(s.DB)
	userRepository.Create(s.Ctx, testUser)
	s.Application.Identities().Create(s.Ctx, testIdentity)

	// Load the identity
	identity, err := s.Application.Identities().LoadWithUser(s.Ctx, testIdentity.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identity)
	require.True(s.T(), identity.IsUser())
}

func (s *identityBlackBoxTest) TestFindIdentityMemberships() {
	// Create an identity
	identity := createAndLoad(s)

	orgName := "Acme Corporation - identityBlackBoxTest.TestFindIdentityMemberships" + uuid.NewV4().String()
	// Create an organization
	orgID, err := s.Application.OrganizationService().CreateOrganization(s.Ctx, identity.ID, orgName)
	require.NoError(s.T(), err)

	// Create a record in the membership table
	err = s.DB.Unscoped().Exec("INSERT INTO membership (member_id, member_of) VALUES (?, ?)", identity.ID, orgID).Error
	require.NoError(s.T(), err)

	// Find the identity's memberships
	associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, identity.ID, nil)
	require.NoError(s.T(), err)

	// There should be 1 entry
	require.Equal(s.T(), 1, len(associations))
	require.Equal(s.T(), orgID, associations[0].IdentityID)
	require.True(s.T(), associations[0].Member)
	require.Equal(s.T(), orgName, associations[0].ResourceName)
}

func (s *identityBlackBoxTest) TestFindIdentityTeamMemberships() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateTeam(g.ID("tm"), g.CreateSpace(g.ID("spc"))).AddMember(g.CreateUser(g.ID("m")))

	// Find the member's memberships
	associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, g.UserByID("m").Identity().ID, nil)
	require.NoError(s.T(), err)

	// There should be 1 entry
	require.Equal(s.T(), 1, len(associations))
	require.Equal(s.T(), g.TeamByID("tm").TeamID(), *associations[0].IdentityID)
	require.True(s.T(), associations[0].Member)
	require.Equal(s.T(), g.TeamByID("tm").TeamName(), associations[0].ResourceName)
	require.Equal(s.T(), g.SpaceByID("spc").SpaceID(), *associations[0].ParentResourceID)
}

// TestFindIdentitiesByResourceTypeWithParentResource creates a combination of spaces/teams and then uses the finder method to find them
func (s *identityBlackBoxTest) TestFindIdentitiesByResourceTypeWithParentResource() {
	g := s.DBTestSuite.NewTestGraph()
	spc := g.CreateSpace(g.ID("spc"))
	t1 := g.CreateTeam(g.ID("t1"), spc)
	t2 := g.CreateTeam(g.ID("t2"), spc)
	t3 := g.CreateTeam(g.ID("t3"), spc)

	spc2 := g.CreateSpace(g.ID("spc2"))
	g.CreateTeam(g.ID("t4"), spc2)
	g.CreateTeam(g.ID("t5"), spc2)

	rt := g.LoadResourceType(authorization.IdentityResourceTypeTeam)

	identities, err := s.Application.Identities().FindIdentitiesByResourceTypeWithParentResource(s.Ctx, rt.ResourceType().ResourceTypeID, spc.SpaceID())
	require.NoError(s.T(), err)
	require.Len(s.T(), identities, 3)
	t1Found := false
	t2Found := false
	t3Found := false
	for i := range identities {
		if identities[i].ID == t1.TeamID() {
			t1Found = true
			require.Equal(s.T(), t1.TeamName(), identities[i].IdentityResource.Name)
		} else if identities[i].ID == t2.TeamID() {
			t2Found = true
			require.Equal(s.T(), t2.TeamName(), identities[i].IdentityResource.Name)
		} else if identities[i].ID == t3.TeamID() {
			t3Found = true
			require.Equal(s.T(), t3.TeamName(), identities[i].IdentityResource.Name)
		}
	}

	require.True(s.T(), t1Found)
	require.True(s.T(), t2Found)
	require.True(s.T(), t3Found)

	identities, err = s.Application.Identities().FindIdentitiesByResourceTypeWithParentResource(s.Ctx, rt.ResourceType().ResourceTypeID, spc2.SpaceID())
	require.NoError(s.T(), err)
	require.Len(s.T(), identities, 2)
}

func createAndLoad(s *identityBlackBoxTest) *account.Identity {
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "someuserTestIdentity2",
		ProviderType: account.KeycloakIDP}

	err := s.Application.Identities().Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")
	// when
	idnt, err := s.Application.Identities().Load(s.Ctx, identity.ID)
	// then
	require.Nil(s.T(), err, "Could not load identity")
	require.Equal(s.T(), "someuserTestIdentity2", idnt.Username)
	return idnt
}
