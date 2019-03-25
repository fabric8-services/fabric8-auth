package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	uuid "github.com/satori/go.uuid"

	"fmt"

	"github.com/jinzhu/gorm"
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
		require.NotEmpty(t, identities)
		// make sure that the deleted identity is not part of the result
		for _, identity := range identities {
			assert.NotEqual(t, identity1.ID(), identity.ID)
		}
	})

	s.T().Run("ok hard delete by identity ID", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		identity1 := g.CreateIdentity()
		// create a second identity
		g.CreateIdentity()

		includeSoftDeletes := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}
		// when hard delete user
		err := s.Application.Identities().Delete(s.Ctx, identity1.ID(), includeSoftDeletes)
		// then
		require.NoError(t, err)

		// check identity is deleted permanently
		identity, err := s.Application.Identities().Load(s.Ctx, identity1.ID(), includeSoftDeletes)
		require.EqualError(t, err, fmt.Sprintf("identity with id '%s' not found", identity1.ID()))
		require.Nil(t, identity)

		identity, err = s.Application.Identities().Load(s.Ctx, identity1.ID())
		require.EqualError(t, err, fmt.Sprintf("identity with id '%s' not found", identity1.ID()))
		require.Nil(t, identity)
	})

	s.T().Run("ok soft delete by identity ID", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		identity1 := g.CreateIdentity()

		includeSoftDeletes := func(db *gorm.DB) *gorm.DB {
			return db.Unscoped()
		}

		// when soft delete identity
		err := s.Application.Identities().Delete(s.Ctx, identity1.ID())
		// then
		require.NoError(t, err)

		identity, err := s.Application.Identities().Load(s.Ctx, identity1.ID(), includeSoftDeletes)
		require.NoError(t, err)

		assert.NotNil(t, identity.DeletedAt)
		assert.Equal(t, identity.ID, identity1.ID())
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

func (s *IdentityRepositoryTestSuite) TestListIdentitiesToNotifyForDeactivation() {

	// given
	ctx := context.Background()
	now := time.Now()
	yesterday := now.Add(-1 * 24 * time.Hour)
	ago65days := now.Add(-65 * 24 * time.Hour) // 65 days since last activity and notified...
	ago40days := now.Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...
	ago70days := now.Add(-70 * 24 * time.Hour) // 70 days since last activity and notified...
	// user/identity1: 40 days since last activity and not notified
	user1 := s.Graph.CreateUser().User()
	identity1 := user1.Identities[0]
	identity1.LastActive = &ago40days
	err := s.Application.Identities().Save(ctx, &identity1)
	require.NoError(s.T(), err)
	// user/identity2: 70 days since last activity and not notified
	user2 := s.Graph.CreateUser().User()
	identity2 := user2.Identities[0]
	identity2.LastActive = &ago70days
	err = s.Application.Identities().Save(ctx, &identity2)
	require.NoError(s.T(), err)
	// noise: user/identity: 1 day since last activity and not notified yet
	user3 := s.Graph.CreateUser().User()
	s.Graph.CreateIdentity(now.Add(-24 * time.Hour))
	identity3 := user3.Identities[0]
	identity3.LastActive = &yesterday
	err = s.Application.Identities().Save(ctx, &identity3)
	require.NoError(s.T(), err)
	// noise: user/identity: 65 days since last activity but banned
	user4 := s.Graph.CreateUser().User()
	identity4 := user4.Identities[0]
	identity4.LastActive = &ago65days
	err = s.Application.Identities().Save(ctx, &identity4)
	require.NoError(s.T(), err)
	user4.Banned = true
	err = s.Application.Users().Save(ctx, user4)

	s.T().Run("no user to notify for deactivation", func(t *testing.T) {
		// given
		lastActivity := now.Add(-90 * 24 * time.Hour) // 90 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToNotifyForDeactivation(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	s.T().Run("one user to notify for deactivation", func(t *testing.T) {
		// given
		lastActivity := now.Add(-60 * 24 * time.Hour) // 60 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToNotifyForDeactivation(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, identity2.ID, result[0].ID)
	})

	s.T().Run("one user to notify for deactivation with limit reached", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToNotifyForDeactivation(ctx, lastActivity, 1)
		// then
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, identity2.ID, result[0].ID)
	})

	s.T().Run("two users to notify for deactivation with limit unreached", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToNotifyForDeactivation(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, identity2.ID, result[0].ID)
		assert.Equal(t, identity1.ID, result[1].ID)
	})

	s.T().Run("two users to notify for deactivation without limit", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToNotifyForDeactivation(ctx, lastActivity, -1)
		// then
		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, identity2.ID, result[0].ID)
		assert.Equal(t, identity1.ID, result[1].ID)
	})

}

func (s *IdentityRepositoryTestSuite) TestListIdentitiesToDeactivate() {
	// given
	ctx := context.Background()
	now := time.Now()
	yesterday := now.Add(-1 * 24 * time.Hour)
	ago65days := now.Add(-65 * 24 * time.Hour) // 65 days since last activity and notified...
	ago40days := now.Add(-40 * 24 * time.Hour) // 40 days since last activity and notified...
	ago70days := now.Add(-70 * 24 * time.Hour) // 70 days since last activity and notified...
	// user/identity1: 40 days since last activity and notified
	user1 := s.Graph.CreateUser().User()
	identity1 := user1.Identities[0]
	identity1.LastActive = &ago40days
	identity1.DeactivationNotification = &yesterday
	err := s.Application.Identities().Save(ctx, &identity1)
	require.NoError(s.T(), err)
	// user/identity2: 70 days since last activity and notified
	user2 := s.Graph.CreateUser().User()
	identity2 := user2.Identities[0]
	identity2.LastActive = &ago70days
	identity2.DeactivationNotification = &yesterday
	err = s.Application.Identities().Save(ctx, &identity2)
	require.NoError(s.T(), err)
	// noise: user/identity: 1 day since last activity and not notified yet
	user3 := s.Graph.CreateUser().User()
	s.Graph.CreateIdentity(now.Add(-24 * time.Hour))
	identity3 := user3.Identities[0]
	identity3.LastActive = &yesterday
	err = s.Application.Identities().Save(ctx, &identity3)
	require.NoError(s.T(), err)
	// noise: user/identity: 65 days since last activity and notified, but also banned
	user4 := s.Graph.CreateUser().User()
	identity4 := user4.Identities[0]
	identity4.LastActive = &ago65days
	identity4.DeactivationNotification = &yesterday
	err = s.Application.Identities().Save(ctx, &identity4)
	require.NoError(s.T(), err)
	user4.Banned = true
	err = s.Application.Users().Save(ctx, user4)

	s.T().Run("no user to notify for deactivation", func(t *testing.T) {
		// given
		lastActivity := now.Add(-90 * 24 * time.Hour) // 90 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToDeactivate(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	s.T().Run("one user to notify for deactivation", func(t *testing.T) {
		// given
		lastActivity := now.Add(-60 * 24 * time.Hour) // 60 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToDeactivate(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, identity2.ID, result[0].ID)
	})

	s.T().Run("one user to notify for deactivation with limit reached", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToDeactivate(ctx, lastActivity, 1)
		// then
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, identity2.ID, result[0].ID)
	})

	s.T().Run("two users to notify for deactivation with limit unreached", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToDeactivate(ctx, lastActivity, 100)
		// then
		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, identity2.ID, result[0].ID)
		assert.Equal(t, identity1.ID, result[1].ID)
	})

	s.T().Run("two users to notify for deactivation without limit", func(t *testing.T) {
		// given
		lastActivity := now.Add(-30 * 24 * time.Hour) // 30 days of inactivity
		// when
		result, err := s.Application.Identities().ListIdentitiesToDeactivate(ctx, lastActivity, -1)
		// then
		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, identity2.ID, result[0].ID)
		assert.Equal(t, identity1.ID, result[1].ID)
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

func (s *IdentityRepositoryTestSuite) TestTouchLastUpdated() {

	s.Run("without lastactive timestamp", func() {
		// given
		identity := s.Graph.CreateIdentity().Identity()
		require.NotNil(s.T(), identity)
		require.Nil(s.T(), identity.LastActive)
		now := time.Now()
		// when
		err := s.Application.Identities().TouchLastActive(s.Ctx, identity.ID)
		require.NoError(s.T(), err)
		// then
		identity = s.Graph.LoadIdentity(identity.ID).Identity()
		assert.True(s.T(), now.Before(*identity.LastActive))
		assert.Nil(s.T(), identity.DeactivationNotification)
	})

	s.Run("with lastactive timestamp", func() {
		// given
		yesterday := time.Now().Add(-24 * time.Hour)
		identity := s.Graph.CreateIdentity(yesterday).Identity()
		require.NotNil(s.T(), identity)
		require.NotNil(s.T(), identity.LastActive)
		now := time.Now()
		// when
		err := s.Application.Identities().TouchLastActive(s.Ctx, identity.ID)
		require.NoError(s.T(), err)
		// then
		identity = s.Graph.LoadIdentity(identity.ID).Identity()
		assert.True(s.T(), now.Before(*identity.LastActive))
		assert.Nil(s.T(), identity.DeactivationNotification)
	})

	s.Run("with deactivation_notification timestamp", func() {
		// given
		yesterday := time.Now().Add(-24 * time.Hour)
		identity := s.Graph.CreateIdentity(yesterday).Identity()
		require.NotNil(s.T(), identity)
		require.NotNil(s.T(), identity.LastActive)
		identity.DeactivationNotification = &yesterday
		err := s.Application.Identities().Save(s.Ctx, identity)
		require.NoError(s.T(), err)
		now := time.Now()
		// when
		err = s.Application.Identities().TouchLastActive(s.Ctx, identity.ID)
		require.NoError(s.T(), err)
		// then
		identity = s.Graph.LoadIdentity(identity.ID).Identity()
		assert.True(s.T(), now.Before(*identity.LastActive))
		assert.Nil(s.T(), identity.DeactivationNotification)
	})
}
