package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTeamREST struct {
	gormtestsupport.DBTestSuite
	testIdentity account.Identity
	service      *goa.Service
}

func (s *TestTeamREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB, "TeamCreatorUser-"+uuid.NewV4().String(), "TestTeam")
	require.Nil(s.T(), err)
}

func TestRunTeamREST(t *testing.T) {
	suite.Run(t, &TestTeamREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestTeamREST) SecuredController(identity account.Identity) (*goa.Service, *TeamController) {
	svc := testsupport.ServiceAsUser("Team-Service", identity)
	return svc, NewTeamController(svc, rest.Application)
}

func (rest *TestTeamREST) UnsecuredController() (*goa.Service, *TeamController) {
	svc := goa.New("Team-Service")
	controller := NewTeamController(svc, rest.Application)
	return svc, controller
}

/*
* This test will attempt to create a new organization
 */
func (rest *TestTeamREST) TestCreateTeamSuccess() {
	service, controller := rest.SecuredController(rest.testIdentity)

	g := rest.DBTestSuite.NewTestGraph()
	spc := g.CreateSpace().AddAdmin(g.LoadIdentity(rest.testIdentity.ID))

	teamName := "Team-" + uuid.NewV4().String()
	payload := &app.CreateTeamPayload{
		Name:    &teamName,
		SpaceID: &spc.Resource().ResourceID,
	}

	_, created := test.CreateTeamCreated(rest.T(), service.Context, service, controller, payload)

	require.NotEmpty(rest.T(), created.TeamID)
}

func (rest *TestTeamREST) TestCreateTeamUnauthorized() {
	service, controller := rest.UnsecuredController()

	teamName := "Unauthorized Team Creation-" + uuid.NewV4().String()
	payload := &app.CreateTeamPayload{
		Name: &teamName,
	}

	test.CreateTeamUnauthorized(rest.T(), service.Context, service, controller, payload)
}

/*
* This test will attempt to create a new team with an empty name
 */
func (rest *TestTeamREST) TestCreateTeamEmptyNameFail() {

	service, controller := rest.SecuredController(rest.testIdentity)
	g := rest.DBTestSuite.NewTestGraph()
	spc := g.CreateSpace().AddAdmin(g.LoadIdentity(rest.testIdentity.ID))

	teamName := ""

	payload := &app.CreateTeamPayload{
		Name:    &teamName,
		SpaceID: &spc.Resource().ResourceID,
	}

	_, err := test.CreateTeamBadRequest(rest.T(), service.Context, service, controller, payload)

	require.NotNil(rest.T(), err)
}

/*
* This test will attempt to list teams for a user
 */
func (rest *TestTeamREST) TestListTeamSuccess() {

	service, controller := rest.SecuredController(rest.testIdentity)

	g := rest.DBTestSuite.NewTestGraph()
	g.CreateTeam(g.ID("t")).AddAdmin(g.LoadIdentity(&rest.testIdentity.ID))

	_, teams := test.ListTeamOK(rest.T(), service.Context, service, controller)

	require.Equal(rest.T(), 1, len(teams.Data))

	team := teams.Data[0]

	require.Equal(rest.T(), g.TeamByID("t").TeamID().String(), team.ID)
	require.Equal(rest.T(), g.TeamByID("t").TeamName(), team.Name)
	require.Equal(rest.T(), 1, len(team.Roles))
	require.Equal(rest.T(), authorization.AdminRole, team.Roles[0])
}

func (rest *TestTeamREST) TestListTeamUnauthorized() {
	service, controller := rest.UnsecuredController()
	test.ListTeamUnauthorized(rest.T(), service.Context, service, controller)
}
