package service_test

import (
	"bytes"
	"context"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	tokenmanager "github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/resource"

	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserProfileServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	clean       func()
	accessToken *string
}

func TestRunUserProfileServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &UserProfileServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *UserProfileServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	resource.Require(s.T(), resource.Remote)
	var err error

	// Get the access token ONCE which we will use for all profile related tests.
	//  - avoid repition in every test.
	token, err := s.generateAccessToken() // TODO: Use a simpler way to do this.
	assert.Nil(s.T(), err)
	s.accessToken = token

	// Get the initial profile state.
	profile, err := s.Application.UserProfileService().Get(context.Background(), *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())
	require.Nil(s.T(), err)
	require.NotNil(s.T(), profile)
}

func (s *UserProfileServiceBlackBoxTest) TearDownTest() {
	s.clean()
}

// ReadTokenSet extracts json with token data from the response
func ReadTokenSet(ctx context.Context, res *http.Response) (*tokenmanager.TokenSet, error) {
	// Read the json out of the response body
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, res.Body)
	if err != nil {
		return nil, err
	}
	jsonString := strings.TrimSpace(buf.String())
	return tokenmanager.ReadTokenSetFromJson(ctx, jsonString)
}

func (s *UserProfileServiceBlackBoxTest) generateAccessToken() (*string, error) {

	client := &http.Client{Timeout: 10 * time.Second}
	tokenEndpoint := s.Configuration.GetOAuthProviderEndpointToken()

	res, err := client.PostForm(tokenEndpoint, url.Values{
		"client_id":     {s.Configuration.GetOAuthProviderClientID()},
		"client_secret": {s.Configuration.GetOAuthProviderClientSecret()},
		"username":      {"testuser"},
		"password":      {"testuser"},
		"grant_type":    {"password"},
	})
	if err != nil {
		return nil, errors.NewInternalError(errs.Wrap(err, "error when obtaining token"))
	}

	t, err := ReadTokenSet(context.Background(), res)
	require.Nil(s.T(), err)
	return t.AccessToken, err
}

func (s *UserProfileServiceBlackBoxTest) TestOAuthUserProfileGet() {
	profile, err := s.Application.UserProfileService().Get(context.Background(), *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())

	require.Nil(s.T(), err)
	assert.NotNil(s.T(), profile)

	keys := reflect.ValueOf(*profile.Attributes).MapKeys()
	assert.NotEqual(s.T(), len(keys), 0)
	assert.NotNil(s.T(), *profile.FirstName)
	assert.NotNil(s.T(), *profile.LastName)
	assert.NotNil(s.T(), *profile.Email)
	assert.NotNil(s.T(), *profile.Attributes)
}
