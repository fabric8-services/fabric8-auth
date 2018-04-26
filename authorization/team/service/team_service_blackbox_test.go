package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type teamServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	teamService teamservice.TeamService
}

func TestRunTeamServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &teamServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *teamServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.teamService = teamservice.NewTeamService(s.Application, s.Application)
}

func (s *teamServiceBlackBoxTest) TestCreateAndListTeamsSuccessful() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("myspace")).AddAdmin(g.CreateUser(g.ID("foo")))

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.teamService.CreateTeam(s.Ctx, g.UserByID("foo").Identity().ID, g.SpaceByID("myspace").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	teams, err := s.teamService.ListTeamsInSpace(s.Ctx, g.UserByID("foo").Identity().ID, g.SpaceByID("myspace").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)
}

func (s *teamServiceBlackBoxTest) TestListTeamsInSpaceForDifferentRoles() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("spc")).
		AddAdmin(g.CreateUser(g.ID("admin"))).
		AddContributor(g.CreateUser(g.ID("contributor"))).
		AddViewer(g.CreateUser(g.ID("viewer")))

	randomUser := g.CreateUser()

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.teamService.CreateTeam(s.Ctx, g.UserByID("admin").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	// First list the spaces as the contributor user, this should work
	teams, err := s.teamService.ListTeamsInSpace(s.Ctx, g.UserByID("contributor").Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)

	// Then list the spaces as the viewer user, this should also work
	teams, err = s.teamService.ListTeamsInSpace(s.Ctx, g.UserByID("viewer").Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)

	// Then list the spaces as the unknown user, this should fail
	teams, err = s.teamService.ListTeamsInSpace(s.Ctx, randomUser.Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForNonSpaceUser() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace()
	user := g.CreateUser()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, user.Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForContributor() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace().AddContributor(g.CreateUser(g.ID("user")))

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, g.UserByID("user").Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForViewer() {
	g := s.DBTestSuite.NewTestGraph()
	space := g.CreateSpace().AddViewer(g.CreateUser(g.ID("user")))

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, g.UserByID("user").Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForUnknownUser() {
	g := s.DBTestSuite.NewTestGraph()
	userIdentityID := uuid.NewV4()
	space := g.CreateSpace()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, userIdentityID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForUnknownSpace() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	spaceID := uuid.NewV4().String()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, user.Identity().ID, spaceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForNonSpaceResource() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	resource := g.CreateResource()

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, user.Identity().ID, resource.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestListTeamsForIdentity() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("spc")).AddAdmin(g.CreateUser(g.ID("admin")))

	randomUser := g.CreateUser()

	teamName := "TestTeam" + uuid.NewV4().String()
	teamID, err := s.teamService.CreateTeam(s.Ctx, g.UserByID("admin").Identity().ID, g.SpaceByID("spc").Resource().ResourceID, teamName)
	require.NoError(s.T(), err)

	// Create a wrapper for the team we just created, then use it to add a member and an admin
	g.LoadTeam(teamID).
		AddMember(g.CreateUser(g.ID("team_member"))).
		AddAdmin(g.CreateUser(g.ID("team_admin")))

	teams, err := s.teamService.ListTeamsForIdentity(s.Ctx, g.UserByID("team_member").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, *teams[0].IdentityID)
	require.Equal(s.T(), g.SpaceByID("spc").Resource().ResourceID, *teams[0].ParentResourceID)
	require.Equal(s.T(), g.SpaceByID("spc").Resource().Name, *teams[0].ParentResourceName)
	require.True(s.T(), teams[0].Member)
	require.Len(s.T(), teams[0].Roles, 0)

	teams, err = s.teamService.ListTeamsForIdentity(s.Ctx, g.UserByID("team_admin").Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), *teamID, *teams[0].IdentityID)
	require.False(s.T(), teams[0].Member)
	require.Len(s.T(), teams[0].Roles, 1)
	require.Equal(s.T(), authorization.AdminRole, teams[0].Roles[0])

	teams, err = s.teamService.ListTeamsForIdentity(s.Ctx, randomUser.Identity().ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 0)
}
