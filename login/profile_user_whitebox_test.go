package login

import (
	"context"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/auth"

	"github.com/fabric8-services/fabric8-auth/login/link"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ProfileUserWhiteboxTest struct {
	testsuite.RemoteTestSuite
	profileService       OAuthServiceUserProfileClient
	loginService         *OAuthServiceProvider
	idpLinkService       link.KeycloakIDPService
	protectedAccessToken string
	userAPIFOrAdminURL   string
	tokenEndpoint        string
}

func TestRunProfileUserWhiteboxTest(t *testing.T) {
	suite.Run(t, &ProfileUserWhiteboxTest{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *ProfileUserWhiteboxTest) SetupSuite() {
	s.RemoteTestSuite.SetupSuite()
	if s.Config.IsOAuthServiceTestsDisabled() {
		s.T().Skip("Skipping OAuth Service tests")
	}
	var err error
	oauthUserProfileService := NewOAuthServiceUserProfileClient()
	s.profileService = *oauthUserProfileService

	s.idpLinkService = link.NewKeycloakIDPServiceClient()

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	s.tokenEndpoint, err = s.Config.GetOAuthServiceEndpointToken(r)
	assert.Nil(s.T(), err)

	// http://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users"
	s.userAPIFOrAdminURL, err = s.Config.GetOAuthServiceEndpointUsers(r)
	assert.Nil(s.T(), err)

	token, err := s.generateProtectedAccessToken()
	assert.Nil(s.T(), err)
	require.NotNil(s.T(), token)
	s.protectedAccessToken = *token
}

func (s *ProfileUserWhiteboxTest) generateProtectedAccessToken() (*string, error) {
	clientID := s.Config.GetOAuthServiceClientID()
	clientSecret := s.Config.GetOAuthServiceSecret()
	token, err := auth.GetProtectedAPIToken(context.Background(), s.tokenEndpoint, clientID, clientSecret)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), token)

	return &token, err
}

func (s *ProfileUserWhiteboxTest) TestPATGenerated() {
	assert.NotEmpty(s.T(), s.protectedAccessToken)
}

func (s *ProfileUserWhiteboxTest) TestOAuthServiceLoadUser() {

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedemail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sbosetestusercreate" + uuid.NewV4().String()
	testEnabled := true
	testEmailVerified := true

	testOAuthServiceUserProfileAttributes := &OAuthServiceUserProfileAttributes{
		ImageURLAttributeName: []string{testImageURL},
		BioAttributeName:      []string{testBio},
		URLAttributeName:      []string{testURL},
	}

	testOAuthServiceUserData := OAuthServiceUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testOAuthServiceUserProfileAttributes,
	}

	s.createUser(&testOAuthServiceUserData)

	retrievedUserProfile, err := s.profileService.loadUser(context.Background(), testUserName, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), retrievedUserProfile)
	require.Equal(s.T(), testEmail, *retrievedUserProfile.Email)
	require.Equal(s.T(), testUserName, *retrievedUserProfile.Username)

}

func (s *ProfileUserWhiteboxTest) createUser(userProfile *OAuthServiceUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.True(s.T(), created)
	return url
}
