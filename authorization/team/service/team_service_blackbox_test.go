package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type teamServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunTeamServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &teamServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *teamServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
}

func (s *teamServiceBlackBoxTest) TestCreateAndListTeamsSuccessful() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("myspace")).AddAdmin(g.CreateUser(g.ID("foo")))

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("foo").Identity().ID, g.SpaceByID("myspace").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	teamName2 := "TestTeam" + uuid.NewV4().String()
	teamID2, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("foo").Identity().ID, g.SpaceByID("myspace").Resource().ResourceID, teamName2)
	require.NoError(s.T(), err)

	g.CreateSpace(g.ID("otherspace")).AddAdmin(g.CreateUser(g.ID("bar")))
	teamName3 := "TestTeam" + uuid.NewV4().String()
	_, err = s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("bar").Identity().ID, g.SpaceByID("otherspace").Resource().ResourceID, teamName3)
	require.NoError(s.T(), err)

	teams, err := s.Application.TeamService().ListTeamsInSpace(s.Ctx, g.UserByID("foo").Identity().ID, g.SpaceByID("myspace").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 2)
	team1Found := false
	team2Found := false

	for i := range teams {
		if teams[i].ID == *teamID {
			team1Found = true
			require.Equal(s.T(), teamName, teams[i].IdentityResource.Name)
		} else if teams[i].ID == *teamID2 {
			team2Found = true
			require.Equal(s.T(), teamName2, teams[i].IdentityResource.Name)
		}
	}

	require.True(s.T(), team1Found)
	require.True(s.T(), team2Found)

	teams, err = s.Application.TeamService().ListTeamsInSpace(s.Ctx, g.UserByID("bar").Identity().ID, g.SpaceByID("otherspace").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
}

func (s *teamServiceBlackBoxTest) TestListTeamsInSpaceForDifferentRoles() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("spc")).
		AddAdmin(g.CreateUser(g.ID("admin"))).
		AddContributor(g.CreateUser(g.ID("contributor"))).
		AddViewer(g.CreateUser(g.ID("viewer")))

	randomUser := g.CreateUser()

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("admin").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	// First list the spaces as the contributor user, this should work
	teams, err := s.Application.TeamService().ListTeamsInSpace(s.Ctx, g.UserByID("contributor").Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)

	// Then list the spaces as the viewer user, this should also work
	teams, err = s.Application.TeamService().ListTeamsInSpace(s.Ctx, g.UserByID("viewer").Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)

	// Then list the spaces as a (random) new user, this should fail
	teams, err = s.Application.TeamService().ListTeamsInSpace(s.Ctx, randomUser.Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.ForbiddenError{}, err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForNonSpaceUser() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace()
	user := g.CreateUser()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, user.Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForContributor() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace().AddContributor(g.CreateUser(g.ID("user")))

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("user").Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForViewer() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace().AddViewer(g.CreateUser(g.ID("user")))

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("user").Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForUnknownUser() {
	g := s.DBTestSuite.NewTestGraph()
	userIdentityID := uuid.NewV4()
	space := g.CreateSpace()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, userIdentityID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForUnknownSpace() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	spaceID := uuid.NewV4().String()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, user.Identity().ID, spaceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForNonSpaceResource() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	resource := g.CreateResource()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.Application.TeamService().CreateTeam(s.Ctx, user.Identity().ID, resource.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestListTeamsForIdentity() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("spc")).AddAdmin(g.CreateUser(g.ID("u1")))
	g.CreateSpace(g.ID("spc2")).AddAdmin(g.UserByID("u1"))

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u1").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	teamName2 := "TestTeam" + uuid.NewV4().String()
	teamID2, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u1").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName2)
	require.NoError(s.T(), err)

	teamName3 := "TestTeam" + uuid.NewV4().String()
	teamID3, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u1").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName3)
	require.NoError(s.T(), err)

	teamName4 := "TestTeam" + uuid.NewV4().String()
	teamID4, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u1").Identity().ID, g.SpaceByID("spc2").Resource().ResourceID, teamName4)
	require.NoError(s.T(), err)

	teamName5 := "TestTeam" + uuid.NewV4().String()
	teamID5, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u1").Identity().ID, g.SpaceByID("spc2").Resource().ResourceID, teamName5)
	require.NoError(s.T(), err)

	g.CreateSpace(g.ID("spc3")).AddAdmin(g.CreateUser(g.ID("u2")))
	teamName6 := "TestTeam" + uuid.NewV4().String()
	teamID6, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u2").Identity().ID, g.SpaceByID("spc3").Resource().ResourceID, teamName6)
	require.NoError(s.T(), err)

	teamName7 := "TestTeam" + uuid.NewV4().String()
	teamID7, err := s.Application.TeamService().CreateTeam(s.Ctx, g.UserByID("u2").Identity().ID, g.SpaceByID("spc3").Resource().ResourceID, teamName7)
	require.NoError(s.T(), err)

	randomUser := g.CreateUser()

	// Add members to the teams we just created, then use it to add a member and an admin
	g.LoadTeam(teamID).
		AddMember(g.CreateUser(g.ID("mbr1"))).
		AddAdmin(g.CreateUser(g.ID("adm1")))

	teams, err := s.Application.TeamService().ListTeamsForIdentity(s.Ctx, g.UserByID("mbr1").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, *teams[0].IdentityID)
	require.Equal(s.T(), g.SpaceByID("spc").Resource().ResourceID, *teams[0].ParentResourceID)
	require.True(s.T(), teams[0].Member)
	require.Len(s.T(), teams[0].Roles, 0)

	teams, err = s.Application.TeamService().ListTeamsForIdentity(s.Ctx, g.UserByID("adm1").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, *teams[0].IdentityID)
	require.False(s.T(), teams[0].Member)
	require.Len(s.T(), teams[0].Roles, 1)
	require.Equal(s.T(), authorization.AdminRole, teams[0].Roles[0])

	g.LoadTeam(teamID2).AddMember(g.UserByID("mbr1"))
	teams, err = s.Application.TeamService().ListTeamsForIdentity(s.Ctx, g.UserByID("mbr1").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 2)
	t1Found := false
	t2Found := false
	for i := range teams {
		if *teams[i].IdentityID == *teamID {
			t1Found = true
			require.Equal(s.T(), teamName, teams[i].ResourceName)
		} else if *teams[i].IdentityID == *teamID2 {
			t2Found = true
			require.Equal(s.T(), teamName2, teams[i].ResourceName)
		}
		require.Equal(s.T(), g.SpaceByID("spc").Resource().ResourceID, *teams[i].ParentResourceID)
		require.True(s.T(), teams[i].Member)
		require.Len(s.T(), teams[i].Roles, 0)
	}
	require.True(s.T(), t1Found)
	require.True(s.T(), t2Found)

	// Add the adm1 user as an admin for team 3, and as a member for team 4
	g.LoadTeam(teamID3).AddAdmin(g.UserByID("adm1"))
	g.LoadTeam(teamID4).AddMember(g.UserByID("adm1"))

	teams, err = s.Application.TeamService().ListTeamsForIdentity(s.Ctx, g.UserByID("adm1").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 3)
	t1Found = false
	t3Found := false
	t4Found := false
	for i := range teams {
		if *teams[i].IdentityID == *teamID {
			t1Found = true
			require.False(s.T(), teams[i].Member)
			require.Equal(s.T(), g.SpaceByID("spc").SpaceID(), *teams[i].ParentResourceID)
		} else if *teams[i].IdentityID == *teamID3 {
			t3Found = true
			require.False(s.T(), teams[i].Member)
			require.Equal(s.T(), teamName3, teams[i].ResourceName)
			require.Len(s.T(), teams[i].Roles, 1)
			require.Equal(s.T(), authorization.AdminRole, teams[i].Roles[0])
			require.Equal(s.T(), g.SpaceByID("spc").SpaceID(), *teams[i].ParentResourceID)
		} else if *teams[i].IdentityID == *teamID4 {
			t4Found = true
			require.True(s.T(), teams[i].Member)
			require.Equal(s.T(), teamName4, teams[i].ResourceName)
			require.Len(s.T(), teams[i].Roles, 0)
			require.Equal(s.T(), g.SpaceByID("spc2").SpaceID(), *teams[i].ParentResourceID)
		}

	}
	require.True(s.T(), t1Found)
	require.True(s.T(), t3Found)
	require.True(s.T(), t4Found)

	g.LoadTeam(teamID5).AddMember(g.CreateUser(g.ID("mbr2")))
	g.LoadTeam(teamID6).AddMember(g.UserByID("mbr2"))
	g.LoadTeam(teamID7).AddMember(g.UserByID("mbr2"))

	teams, err = s.Application.TeamService().ListTeamsForIdentity(s.Ctx, g.UserByID("mbr2").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 3)

	t5Found := false
	t6Found := false
	t7Found := false

	for i := range teams {
		if *teams[i].IdentityID == *teamID5 {
			t5Found = true
			require.Equal(s.T(), g.SpaceByID("spc2").SpaceID(), *teams[i].ParentResourceID)
		} else if *teams[i].IdentityID == *teamID6 {
			t6Found = true
			require.Equal(s.T(), g.SpaceByID("spc3").SpaceID(), *teams[i].ParentResourceID)
		} else if *teams[i].IdentityID == *teamID7 {
			t7Found = true
			require.Equal(s.T(), g.SpaceByID("spc3").SpaceID(), *teams[i].ParentResourceID)
		}
		require.True(s.T(), teams[i].Member)
		require.Len(s.T(), teams[i].Roles, 0)
	}

	require.True(s.T(), t5Found)
	require.True(s.T(), t6Found)
	require.True(s.T(), t7Found)

	teams, err = s.Application.TeamService().ListTeamsForIdentity(s.Ctx, randomUser.Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 0)
}
