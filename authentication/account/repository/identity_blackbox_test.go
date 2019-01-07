package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/rest"
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
		g := s.NewTestGraph(t)
		identity1 := g.CreateIdentity()
		// create a second identity
		g.CreateIdentity()
		// when
		err := s.Application.Identities().Delete(s.Ctx, identity1.ID())
		// then
		assert.Nil(t, err)
		identities, err := s.Application.Identities().List(s.Ctx)
		require.NoError(t, err, "Could not list identities")
		require.True(t, len(identities) >= 1)
		// make sure that the deleted identity is not part of the result
		for _, identity := range identities {
			assert.NotEqual(t, identity1.ID(), identity.ID)
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
		g := s.NewTestGraph(t)
		identity := g.CreateIdentity()
		// when
		result, err := s.Application.Identities().Load(s.Ctx, identity.ID())
		// then
		require.NoError(t, err, "Could not load identity")
		assert.Equal(t, identity.Identity().Username, result.Username)
	})
}

func (s *IdentityRepositoryTestSuite) TestIdentitiesWithClusterURL() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		// Create test user & identity
		g := s.NewTestGraph(t)
		identities := make([]account.Identity, 0)
		for i := 0; i < 5; i++ {
			user := g.CreateUser()
			identities = append(identities, *user.Identity())
		}

		// when
		identitiesWithClusterURL, err := s.Application.Identities().GetIdentitiesWithClusterURL(s.Ctx)
		// then
		require.NoError(t, err, "Could not load identity")
		require.NotEmpty(t, identitiesWithClusterURL)

		for i := 0; i < 5; i++ {
			identity := identities[i]
			require.Contains(t, identitiesWithClusterURL, identity.ID)
			assert.Equal(t, identitiesWithClusterURL[identity.ID], rest.AddTrailingSlashToURL(identity.User.Cluster))
		}
	})
}

func (s *IdentityRepositoryTestSuite) TestIdentityExists() {

	s.T().Run("identity exists", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		identity := g.CreateIdentity()
		// when
		err := s.Application.Identities().CheckExists(s.Ctx, identity.ID().String())
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
		g := s.NewTestGraph(t)
		identity := g.CreateIdentity()
		// when
		identity.Identity().Username = "newusernameTestIdentity"
		err := s.Application.Identities().Save(s.Ctx, identity.Identity())
		// then
		require.NoError(t, err, "Could not update identity")
	})
}

func (s *IdentityRepositoryTestSuite) TestLoadWithUser() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		// Create test user & identity
		g := s.NewTestGraph(t)
		user := g.CreateUser()
		identity := user.Identity()
		// when
		// Check load
		result, err := s.Application.Identities().LoadWithUser(s.Ctx, identity.ID)
		// then
		require.NoError(t, err)
		require.NotNil(t, identity)
		result.CreatedAt = identity.CreatedAt // Align timestamps
		result.UpdatedAt = identity.UpdatedAt
		result.Lifecycle = identity.Lifecycle
		result.User.UpdatedAt = identity.User.UpdatedAt
		result.User.CreatedAt = identity.User.CreatedAt
		result.User.Lifecycle = identity.User.Lifecycle
		assert.Equal(t, identity, result)
		assert.True(t, result.IsUser())
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
			g := s.NewTestGraph(t)
			identity := g.CreateIdentity()
			// when
			_, err := s.Application.Identities().LoadWithUser(s.Ctx, identity.ID())
			// then
			assert.EqualError(t, err, errors.NewNotFoundError("user for identity", identity.ID().String()).Error())
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
		associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, g.UserByID("m").IdentityID(), nil)
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
		associations, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, g.UserByID("m").IdentityID(), nil)
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
		// given
		g := s.NewTestGraph(t)
		team := g.CreateTeam()
		user := g.CreateUser()
		team.AddMember(user)
		// when
		memberships, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, user.IdentityID(), nil)
		// then
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

func (s *IdentityRepositoryTestSuite) TestRemoveMember() {
	// Create a team, and a user, and add the user as a member to the team
	team := s.Graph.CreateTeam()
	user := s.Graph.CreateUser()
	team.AddMember(user)

	// Confirm that the membership exists
	memberships, err := s.Application.Identities().FindIdentityMemberships(s.Ctx, user.IdentityID(), nil)
	require.NoError(s.T(), err)
	require.Len(s.T(), memberships, 1)

	// Remove the membership
	err = s.Application.Identities().RemoveMember(s.Ctx, team.TeamID(), user.IdentityID())
	require.NoError(s.T(), err)

	// Confirm that the membership has been removed
	memberships, err = s.Application.Identities().FindIdentityMemberships(s.Ctx, user.IdentityID(), nil)
	require.NoError(s.T(), err)
	require.Len(s.T(), memberships, 0)
}
