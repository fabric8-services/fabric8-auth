package controller_test

import (
	"testing"

	"time"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"os"
)

type TestStatusREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunStatusREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestStatusREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestStatusREST) SecuredController() (*goa.Service, *StatusController) {
	svc := testsupport.ServiceAsUser("Status-Service", testsupport.TestIdentity)
	return svc, NewStatusController(svc, rest.DB, rest.Configuration)
}

func (rest *TestStatusREST) UnSecuredController() (*goa.Service, *StatusController) {
	svc := goa.New("Status-Service")
	return svc, NewStatusController(svc, rest.DB, rest.Configuration)
}

func (rest *TestStatusREST) TestShowStatusOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()
	_, res := test.ShowStatusOK(t, svc.Context, svc, ctrl)

	assert.Equal(t, "0", res.Commit, "Commit not found")
	assert.Equal(t, StartTime, res.StartTime, "StartTime is not correct")
	assert.NotNil(t, res.Error)

	_, err := time.Parse("2006-01-02T15:04:05Z", res.StartTime)
	assert.Nil(t, err, "Incorrect layout of StartTime")

	require.NotNil(t, res.DevMode)
	assert.True(t, *res.DevMode)
}

func (rest *TestStatusREST) TestShowStatusFailWithDefaultConfig() {
	existingDevMode := os.Getenv("AUTH_DEVELOPER_MODE_ENABLED")
	defer func() {
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
		rest.resetConfiguration()
	}()

	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "false")
	svc, ctrl := rest.UnSecuredController()
	_, res := test.ShowStatusServiceUnavailable(rest.T(), svc.Context, svc, ctrl)
	assert.NotNil(rest.T(), res.Error)
}

func (rest *TestStatusREST) resetConfiguration() {
	config, err := configuration.GetConfigurationData()
	require.Nil(rest.T(), err)
	rest.Configuration = config
}
