package login_test

import (
	"context"
	"encoding/json"
	"github.com/fabric8-services/fabric8-auth/configuration"
	autherror "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"github.com/goadesign/goa/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestLoginIDP(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &loginIDPTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})

}

type loginIDPTestSuite struct {
	gormtestsupport.DBTestSuite
	IDPServer *httptest.Server
	config    *configuration.ConfigurationData
}

func (s *loginIDPTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.IDPServer = createServer(serve)

}

func (s *loginIDPTestSuite) TearDownSuite() {
	s.IDPServer.CloseClientConnections()
	s.IDPServer.Close()
}

func (s *loginIDPTestSuite) getCustomConfig() *configuration.ConfigurationData {
	idpServerURL := "http://" + s.IDPServer.Listener.Addr().String() + "/"
	os.Setenv("AUTH_ENDPOINT_USERINFO", idpServerURL)
	config, err := configuration.GetConfigurationData()
	require.Nil(s.T(), err)
	return config
}

func (s *loginIDPTestSuite) TestProfileOK() {
	loginIDP := login.NewLoginIdentityProvider(s.getCustomConfig())
	data, err := loginIDP.Profile(context.Background(), oauth2.Token{})
	require.Nil(s.T(), err)
	require.NotNil(s.T(), data)
	s.compareResponse(loginIDPResponseSample, *data)
}

func (s *loginIDPTestSuite) TestProfileInternalError() {
	// this will try reaching keycloak
	loginIDP := login.NewLoginIdentityProvider(s.Configuration)
	data, err := loginIDP.Profile(context.Background(), oauth2.Token{})
	require.Error(s.T(), err)
	require.Nil(s.T(), data)
	require.IsType(s.T(), autherror.InternalError{}, errors.Cause(err))
}

func (s *loginIDPTestSuite) compareResponse(response login.LoginIdentityProviderResponse, profile oauth.UserProfile) {
	assert.Equal(s.T(), profile.Username, response.Username)
	assert.Equal(s.T(), profile.Company, response.Company)
	assert.Equal(s.T(), profile.Email, response.Email)
	assert.Equal(s.T(), profile.EmailVerified, response.EmailVerified)
	assert.Equal(s.T(), profile.FamilyName, response.FamilyName)
}

// Run a mocked IDP server

var loginIDPResponseSample login.LoginIdentityProviderResponse = login.LoginIdentityProviderResponse{
	Username:      "username",
	GivenName:     "gname",
	FamilyName:    "fname",
	Email:         "email",
	EmailVerified: true,
	Company:       "company",
	Approved:      true,
	Subject:       uuid.NewV4().String(),
}

func createServer(handle func(http.ResponseWriter, *http.Request)) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handle)
	return httptest.NewServer(mux)
}

func serve(rw http.ResponseWriter, req *http.Request) {
	inBytes, _ := json.Marshal(loginIDPResponseSample)
	rw.Write(inBytes)
}
