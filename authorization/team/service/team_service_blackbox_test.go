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

func (s *teamServiceBlackBoxTest) TestCreateTeamSuccessful() {
	g := s.DBTestSuite.NewTestGraph()
	g.CreateSpace(g.ID("myspace")).AddAdmin(g.CreateUser(g.ID("foo")))

	_, err := s.teamService.CreateTeam(s.Ctx, g.GetUser("foo").Identity().ID, g.GetSpace("myspace").Resource().ResourceID, "TestTeam"+uuid.NewV4().String())
	require.NoError(s.T(), err)
}
