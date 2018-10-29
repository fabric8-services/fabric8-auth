package controller_test

import (
	"os"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/goadesign/goa"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	expectedDefaultConfDevModeErrorMessage  = "Error: /etc/fabric8/service-account-secrets.conf is not used; developer Mode is enabled; default service account private key is used; default service account private key ID is used; default user account private key is used; default user account private key ID is used; default DB password is used; default auth provider client secret is used; default GitHub client secret is used; no restrictions for valid redirect URLs; notification service url is empty; OSO Reg App url is empty; OSO Reg App admin username is empty; OSO Reg App admin token is empty; environment is expected to be set to 'production' or 'prod-preview'; Sentry DSN is empty"
	expectedDefaultConfProdModeErrorMessage = "Error: /etc/fabric8/service-account-secrets.conf is not used; default service account private key is used; default service account private key ID is used; default user account private key is used; default user account private key ID is used; default DB password is used; default auth provider client secret is used; default GitHub client secret is used; notification service url is empty; OSO Reg App url is empty; OSO Reg App admin username is empty; OSO Reg App admin token is empty; environment is expected to be set to 'production' or 'prod-preview'; Sentry DSN is empty"
)

type TestStatusREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunStatusREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestStatusREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestStatusREST) UnSecuredController() (*goa.Service, *StatusController) {
	svc := goa.New("Status-Service")
	return svc, NewStatusController(svc, NewGormDBChecker(rest.DB), rest.Configuration)
}

func (rest *TestStatusREST) UnSecuredControllerWithUnreachableDB() (*goa.Service, *StatusController) {
	svc := goa.New("Status-Service")
	return svc, NewStatusController(svc, &dummyDBChecker{}, rest.Configuration)
}

func (rest *TestStatusREST) TestShowStatusInDevModeOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()
	_, res := test.ShowStatusOK(t, svc.Context, svc, ctrl)

	assert.Equal(t, "0", res.Commit, "Commit not found")
	assert.Equal(t, StartTime, res.StartTime, "StartTime is not correct")
	assert.Equal(t, expectedDefaultConfDevModeErrorMessage, res.ConfigurationStatus)
	assert.Equal(t, "OK", res.DatabaseStatus)

	_, err := time.Parse("2006-01-02T15:04:05Z", res.StartTime)
	assert.Nil(t, err, "Incorrect layout of StartTime")

	require.NotNil(t, res.DevMode)
	assert.True(t, *res.DevMode)
}

func (rest *TestStatusREST) TestShowStatusWithoutDBFails() {
	svc, ctrl := rest.UnSecuredControllerWithUnreachableDB()
	_, res := test.ShowStatusServiceUnavailable(rest.T(), svc.Context, svc, ctrl)

	assert.Equal(rest.T(), "Error: DB is unreachable", res.DatabaseStatus)
}

func (rest *TestStatusREST) TestShowStatusWithDefaultConfigInProdModeFails() {
	existingDevMode := os.Getenv("AUTH_DEVELOPER_MODE_ENABLED")
	defer func() {
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
		rest.resetConfiguration()
	}()

	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "false")
	rest.resetConfiguration()
	svc, ctrl := rest.UnSecuredController()
	_, res := test.ShowStatusServiceUnavailable(rest.T(), svc.Context, svc, ctrl)
	assert.Equal(rest.T(), expectedDefaultConfProdModeErrorMessage, res.ConfigurationStatus)
	assert.Equal(rest.T(), "OK", res.DatabaseStatus)

	// If the DB is not available then status should return the corresponding error
	svc, ctrl = rest.UnSecuredControllerWithUnreachableDB()
	_, res = test.ShowStatusServiceUnavailable(rest.T(), svc.Context, svc, ctrl)

	assert.Equal(rest.T(), expectedDefaultConfProdModeErrorMessage, res.ConfigurationStatus)
	assert.Equal(rest.T(), "Error: DB is unreachable", res.DatabaseStatus)
}

func (rest *TestStatusREST) resetConfiguration() {
	config, err := configuration.GetConfigurationData()
	require.Nil(rest.T(), err)
	rest.Configuration = config
}

type dummyDBChecker struct {
}

func (c *dummyDBChecker) Ping() error {
	return errors.New("DB is unreachable")
}
