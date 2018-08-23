package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IdentityRepositoryTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestIdentityRepository(t *testing.T) {
	suite.Run(t, &IdentityRepositoryTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *IdentityRepositoryTestSuite) TestDelete() {

	s.T().Run("ok by identity ID", func(t *testing.T) {
		// given
		identity := &repository.Identity{
			ID:           uuid.NewV4(),
			Username:     "someuserTestIdentity",
			ProviderType: repository.KeycloakIDP}
		identity2 := &repository.Identity{
			ID:           uuid.NewV4(),
			Username:     "onemoreuserTestIdentity",
			ProviderType: repository.KeycloakIDP}
		err := s.Application.Identities().Create(s.Ctx, identity)
		require.NoError(t, err, "Could not create identity")
		err = s.Application.Identities().Create(s.Ctx, identity2)
		require.NoError(t, err, "Could not create identity")
		// when
		err = s.Application.Identities().Delete(s.Ctx, identity.ID)
		// then
		assert.Nil(t, err)
		identities, err := s.Application.Identities().List(s.Ctx)
		require.NoError(t, err, "Could not list identities")
		require.True(t, len(identities) > 0)
		for _, ident := range identities {
			require.NotEqual(t, "someuserTestIdentity", ident.Username)
		}
	})

	s.T().Run("ok by resource ID", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		team := g.CreateTeam()
		err := s.Application.Identities().CheckExists(s.Ctx, team.TeamID().String())
		require.NoError(t, err)
		anotherTeam := g.CreateTeam()
		// when
		err = s.Application.Identities().DeleteForResource(s.Ctx, team.ResourceID())
		// then
		require.NoError(t, err)
		// Team is gone
		err = s.Application.Identities().CheckExists(s.Ctx, team.TeamID().String())
		testsupport.AssertError(t, err, errors.NotFoundError{}, "identities with id '%s' not found", team.TeamID())
		// The other team is still present
		err = s.Application.Identities().CheckExists(s.Ctx, anotherTeam.TeamID().String())
		require.NoError(t, err)
		// Delete action doesn't fail even if we try to delete an identities for a resource without any assosiated identity
		err = s.Application.Identities().DeleteForResource(s.Ctx, team.ResourceID())
		require.NoError(t, err)
	})

}

func (s *IdentityRepositoryTestSuite) TestLoad() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		identity := &repository.Identity{
			ID:           uuid.NewV4(),
			Username:     "user-load-" + uuid.NewV4().String(),
			ProviderType: repository.KeycloakIDP}
		err := s.Application.Identities().Create(s.Ctx, identity)
		require.NoError(t, err, "Could not create identity")
		// when
		idnt, err := s.Application.Identities().Load(s.Ctx, identity.ID)
		// then
		require.NoError(t, err, "Could not load identity")
		assert.Equal(t, identity.Username, idnt.Username)
	})
}

func (s *IdentityRepositoryTestSuite) TestIdentityExists() {

	s.T().Run("identity exists", func(t *testing.T) {
		// given
		identity := &repository.Identity{
			ID:           uuid.NewV4(),
			Username:     "user-exists-" + uuid.NewV4().String(),
			ProviderType: repository.KeycloakIDP}
		err := s.Application.Identities().Create(s.Ctx, identity)
		require.NoError(t, err, "Could not create identity")
		// when
		err = s.Application.Identities().CheckExists(s.Ctx, identity.ID.String())
		// then
		require.NoError(t, err)
	})

	s.T().Run("identity doesn't exist", func(t *testing.T) {
		err := s.Application.Identities().CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (s *IdentityRepositoryTestSuite) TestSave() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		identity := &repository.Identity{
			ID:           uuid.NewV4(),
			Username:     "user-save" + uuid.NewV4().String(),
			ProviderType: repository.KeycloakIDP}
		err := s.Application.Identities().Create(s.Ctx, identity)
		require.NoError(t, err, "Could not create identity")
		// when
		identity.Username = "newusernameTestIdentity"
		err = s.Application.Identities().Save(s.Ctx, identity)
		// then
		require.NoError(t, err, "Could not update identity")
	})
}

func (s *IdentityRepositoryTestSuite) TestLoadWithUser() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		// Create test user & identity
		testUser := &repository.User{
			ID:       uuid.NewV4(),
			Email:    uuid.NewV4().String(),
			FullName: "TestLoadIdentityAndUserOK Developer",
			Cluster:  "https://api.starter-us-east-2a.openshift.com",
		}
		testIdentity := &repository.Identity{
			Username:     "TestLoadIdentityAndUserOK" + uuid.NewV4().String(),
			ProviderType: repository.KeycloakIDP,
			User:         *testUser,
		}
		userRepository := repository.NewUserRepository(s.DB)
		userRepository.Create(s.Ctx, testUser)
		s.Application.Identities().Create(s.Ctx, testIdentity)
		// when
		// Check load
		identity, err := s.Application.Identities().LoadWithUser(s.Ctx, testIdentity.ID)
		// then
		require.NoError(t, err)
		require.NotNil(t, identity)
		testIdentity.CreatedAt = identity.CreatedAt // Align timestamps
		testIdentity.UpdatedAt = identity.UpdatedAt
		testIdentity.Lifecycle = identity.Lifecycle
		testIdentity.User.UpdatedAt = identity.User.UpdatedAt
		testIdentity.User.CreatedAt = identity.User.CreatedAt
		testIdentity.User.Lifecycle = identity.User.Lifecycle
		assert.Equal(t, testIdentity, identity)
		assert.True(t, identity.IsUser())
	})

	s.T().Run("failure", func(t *testing.T) {

		s.T().Run("identity does not exist", func(t *testing.T) {
			// given
			// Identity does not exist
			id := uuid.NewV4()
			// when
			_, err := s.Application.Identities().LoadWithUser(s.Ctx, id)
			// then
			assert.EqualError(t, err, errors.NewNotFoundError("identity", id.String()).Error())
		})

		s.T().Run("identity without user", func(t *testing.T) {
			// given
			// Identity exists but not associated with any user
			identity := &repository.Identity{
				ID:           uuid.NewV4(),
				Username:     "user-load-" + uuid.NewV4().String(),
				ProviderType: repository.KeycloakIDP}
			err := s.Application.Identities().Create(s.Ctx, identity)
			require.NoError(t, err, "Could not create identity")
			// when
			_, err = s.Application.Identities().LoadWithUser(s.Ctx, identity.ID)
			// then
			assert.EqualError(t, err, errors.NewNotFoundError("user for identity", identity.ID.String()).Error())
		})
	})

}

func (s *IdentityRepositoryTestSuite) TestFindIdentityMemberships() {

	s.T().Run("user member of org", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		g.CreateOrganization(g.ID("org")).AddMember(g.CreateUser(g.ID("m")))
		// when
		// Find the identity's memberships
		associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, g.UserByID("m").Identity().ID, nil)
		// then
		require.NoError(t, err)
		// There should be 1 entry
		require.Len(t, associations, 1)
		assert.Equal(t, g.OrganizationByID("org").OrganizationID(), *associations[0].IdentityID)
		assert.True(t, associations[0].Member)
		assert.Equal(t, g.OrganizationByID("org").OrganizationName(), associations[0].ResourceName)
	})

	s.T().Run("user member of a team", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		g.CreateTeam(g.ID("tm"), g.CreateSpace(g.ID("space"))).AddMember(g.CreateUser(g.ID("m")))
		// when: find the member's memberships
		associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, g.UserByID("m").Identity().ID, nil)
		// then: there should be 1 entry
		require.NoError(t, err)
		require.Len(t, associations, 1)
		assert.Equal(t, g.TeamByID("tm").TeamID(), *associations[0].IdentityID)
		assert.True(t, associations[0].Member)
		assert.Equal(t, g.TeamByID("tm").TeamName(), associations[0].ResourceName)
		assert.Equal(t, g.SpaceByID("space").SpaceID(), *associations[0].ParentResourceID)
	})

}

// TestFindIdentitiesByResourceTypeWithParentResource creates a combination of spaces/teams and then uses the finder method to find them
func (s *IdentityRepositoryTestSuite) TestFindIdentitiesByResourceTypeWithParentResource() {

	s.T().Run("on multiple spaces", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		space1 := g.CreateSpace(g.ID("space"))
		t1 := g.CreateTeam(g.ID("t1"), space1)
		t2 := g.CreateTeam(g.ID("t2"), space1)
		t3 := g.CreateTeam(g.ID("t3"), space1)
		space2 := g.CreateSpace(g.ID("space2"))
		g.CreateTeam(g.ID("t4"), space2)
		g.CreateTeam(g.ID("t5"), space2)
		rt := g.LoadResourceType(authorization.IdentityResourceTypeTeam)
		// when searching on space1
		identities, err := s.Application.Identities().FindIdentitiesByResourceTypeWithParentResource(s.Ctx, rt.ResourceType().ResourceTypeID, space1.SpaceID())
		// then
		require.NoError(t, err)
		require.Len(t, identities, 3)
		t1Found := false
		t2Found := false
		t3Found := false
		for i := range identities {
			if identities[i].ID == t1.TeamID() {
				t1Found = true
				require.Equal(t, t1.TeamName(), identities[i].IdentityResource.Name)
			} else if identities[i].ID == t2.TeamID() {
				t2Found = true
				require.Equal(t, t2.TeamName(), identities[i].IdentityResource.Name)
			} else if identities[i].ID == t3.TeamID() {
				t3Found = true
				require.Equal(t, t3.TeamName(), identities[i].IdentityResource.Name)
			}
		}

		require.True(t, t1Found)
		require.True(t, t2Found)
		require.True(t, t3Found)
		// when searching on space2
		identities, err = s.Application.Identities().FindIdentitiesByResourceTypeWithParentResource(s.Ctx, rt.ResourceType().ResourceTypeID, space2.SpaceID())
		// then
		require.NoError(t, err)
		require.Len(t, identities, 2)
	})
}

func (s *IdentityRepositoryTestSuite) TestAddMember() {

	s.T().Run("ok", func(t *testing.T) {
		g := s.NewTestGraph(t)
		team := g.CreateTeam()
		user := g.CreateUser()

		err := s.Application.Identities().AddMember(s.Ctx, team.TeamID(), user.IdentityID())
		require.NoError(t, err)

		memberships, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, user.IdentityID(), nil)
		require.NoError(t, err)

		// Require that the user we created has 1 membership, and that it is in the team we created
		require.Len(t, memberships, 1)
		assert.Equal(t, team.TeamID(), *memberships[0].IdentityID)
		assert.True(t, memberships[0].Member)
	})

	s.T().Run("failure", func(t *testing.T) {

		t.Run("invalid team identity", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			// when
			err := s.Application.Identities().AddMember(s.Ctx, uuid.NewV4(), user.IdentityID())
			// then
			require.Error(t, err)
		})

		t.Run("invalid member identity", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			team := g.CreateTeam()
			// when
			err := s.Application.Identities().AddMember(s.Ctx, team.TeamID(), uuid.NewV4())
			// then
			require.Error(t, err)
		})

		t.Run("non member identity", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			member := g.CreateUser()
			// when
			err := s.Application.Identities().AddMember(s.Ctx, user.IdentityID(), member.IdentityID())
			// then
			require.Error(t, err)
		})

		t.Run("duplicate membership", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			team := g.CreateTeam()
			user := g.CreateUser()
			err := s.Application.Identities().AddMember(s.Ctx, team.TeamID(), user.IdentityID())
			require.NoError(t, err)
			// when
			err = s.Application.Identities().AddMember(s.Ctx, team.TeamID(), user.IdentityID())
			// then
			require.Error(t, err)
		})

	})
}
