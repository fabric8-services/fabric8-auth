package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type spaceServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunSpaceServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &spaceServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *spaceServiceBlackBoxTest) TestCreateOK() {

}

func (s *spaceServiceBlackBoxTest) _TestDeleteOK() {
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
