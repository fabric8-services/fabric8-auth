package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"path/filepath"
)

type TestTokenRemoteREST struct {
	suite.Suite
	config  *configuration.ConfigurationData
	testDir string
}

func TestRunTokenRemoteREST(t *testing.T) {
	resource.Require(t, resource.Remote)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		t.Fatalf("Failed to setup the Configuration: %s", err.Error())
	}
	suite.Run(t, &TestTokenRemoteREST{config: config})
}

func (rest *TestTokenRemoteREST) SetupTest() {
	rest.testDir = filepath.Join("test-files", "token")
}

func (rest *TestTokenRemoteREST) TearDownTest() {
}

func (rest *TestTokenRemoteREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := goa.New("Token-Service")
	manager, err := token.NewManager(rest.config)
	require.Nil(rest.T(), err)
	return svc, NewTokenController(svc, nil, manager, rest.config, nil)
}

func (rest *TestTokenRemoteREST) TestPublicKeys() {
	svc, ctrl := rest.UnSecuredController()

	rest.T().Run("file not found", func(t *testing.T) {
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, nil)
		rest.checkJWK(keys)
	})
	rest.T().Run("file not found", func(t *testing.T) {
		jwk := "jwk"
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, &jwk)
		rest.checkJWK(keys)
	})
	rest.T().Run("file not found", func(t *testing.T) {
		pem := "pem"
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, &pem)
		rest.checkPEM(keys)
	})
}

func (rest *TestTokenRemoteREST) checkPEM(keys *app.PublicKeys) {
	compareWithGolden(rest.T(), filepath.Join(rest.testDir, "keys", "ok_pem.golden.json"), keys)
}

func (rest *TestTokenRemoteREST) checkJWK(keys *app.PublicKeys) {
	compareWithGolden(rest.T(), filepath.Join(rest.testDir, "keys", "ok_jwk.golden.json"), keys)
}
