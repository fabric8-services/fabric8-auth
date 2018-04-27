package login

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/auth"
	"net/http"
	"testing"

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
	profileService       KeycloakUserProfileClient
	loginService         *KeycloakOAuthProvider
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
	if s.Config.IsKeycloakTestsDisabled() {
		s.T().Skip("Skipping Keycloak tests")
	}
	var err error
	keycloakUserProfileService := NewKeycloakUserProfileClient()
	s.profileService = *keycloakUserProfileService

	s.idpLinkService = link.NewKeycloakIDPServiceClient()

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	s.tokenEndpoint, err = s.Config.GetKeycloakEndpointToken(r)
	assert.Nil(s.T(), err)

	// http://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users"
	s.userAPIFOrAdminURL, err = s.Config.GetKeycloakEndpointUsers(r)
	assert.Nil(s.T(), err)

	token, err := s.generateProtectedAccessToken()
	assert.Nil(s.T(), err)
	require.NotNil(s.T(), token)
	s.protectedAccessToken = *token
}

func (s *ProfileUserWhiteboxTest) generateProtectedAccessToken() (*string, error) {
	clientID := s.Config.GetKeycloakClientID()
	clientSecret := s.Config.GetKeycloakSecret()
	token, err := auth.GetProtectedAPIToken(context.Background(), s.tokenEndpoint, clientID, clientSecret)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), token)

	return &token, err
}

func (s *ProfileUserWhiteboxTest) TestPATGenerated() {
	assert.NotEmpty(s.T(), s.protectedAccessToken)
}

func (s *ProfileUserWhiteboxTest) TestKeycloakLoadUser() {

	testFirstName := "updatedFirstNameAgainNew" + uuid.Must(uuid.NewV4()).String()
	testLastName := "updatedLastNameNew" + uuid.Must(uuid.NewV4()).String()
	testEmail := "updatedemail" + uuid.Must(uuid.NewV4()).String() + "@email.com"
	testBio := "updatedBioNew" + uuid.Must(uuid.NewV4()).String()
	testURL := "updatedURLNew" + uuid.Must(uuid.NewV4()).String()
	testImageURL := "updatedBio" + uuid.Must(uuid.NewV4()).String()
	testUserName := "sbosetestusercreate" + uuid.Must(uuid.NewV4()).String()
	testEnabled := true
	testEmailVerified := true

	testKeycloakUserProfileAttributes := &KeycloakUserProfileAttributes{
		ImageURLAttributeName: []string{testImageURL},
		BioAttributeName:      []string{testBio},
		URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := KeytcloakUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testKeycloakUserProfileAttributes,
	}

	s.createUser(&testKeycloakUserData)

	retrievedUserProfile, err := s.profileService.loadUser(context.Background(), testUserName, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), retrievedUserProfile)
	require.Equal(s.T(), testEmail, *retrievedUserProfile.Email)
	require.Equal(s.T(), testUserName, *retrievedUserProfile.Username)

}

func (s *ProfileUserWhiteboxTest) createUser(userProfile *KeytcloakUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.True(s.T(), created)
	return url
}
