package service_test

import (
	"testing"

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
	require.Equal(s.T(), teamID, teams[0].ID)
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
	require.Equal(s.T(), teamID, teams[0].ID)
	require.Equal(s.T(), teamName, teams[0].IdentityResource.Name)

	// Then list the spaces as the viewer user, this should also work
	teams, err = s.teamService.ListTeamsInSpace(s.Ctx, g.UserByID("viewer").Identity().ID, g.SpaceByID("spc").Resource().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), teams, 1)
	require.Equal(s.T(), teamID, teams[0].ID)
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
	user := g.CreateUser()
	space := g.CreateSpace().AddContributor(user)

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, user.Identity().ID, space.Resource().ResourceID, teamName)
	require.Error(s.T(), err)
}

func (s *teamServiceBlackBoxTest) TestCreateTeamFailsForViewer() {
	g := s.DBTestSuite.NewTestGraph()
	user := g.CreateUser()
	space := g.CreateSpace().AddViewer(user)

	teamName := "TestTeam" + uuid.NewV4().String()
	_, err := s.teamService.CreateTeam(s.Ctx, user.Identity().ID, space.Resource().ResourceID, teamName)
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
