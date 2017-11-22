package login_test

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"net/http"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/auth"
	keycloakLink "github.com/fabric8-services/fabric8-auth/login/link"

	"github.com/goadesign/goa"
	_ "github.com/lib/pq"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ProfileUserBlackBoxTest struct {
	testsuite.RemoteTestSuite
	clean                func()
	profileService       login.UserProfileService
	loginService         *login.KeycloakOAuthProvider
	idpLinkService       keycloakLink.KeycloakIDPService
	protectedAccessToken string
	userAPIFOrAdminURL   string
	tokenEndpoint        string
}

func TestRunProfileUserBlackBoxTest(t *testing.T) {
	if configuration.IsKeycloakTestsDisabled() {
		t.Skip("Skipping Keycloak AuthZ tests")
	}
	suite.Run(t, &ProfileUserBlackBoxTest{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *ProfileUserBlackBoxTest) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	var err error
	s.Config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}

	keycloakUserProfileService := login.NewKeycloakUserProfileClient()
	s.profileService = keycloakUserProfileService

	s.idpLinkService = keycloakLink.NewKeycloakIDPServiceClient()

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	s.tokenEndpoint, err = s.Config.GetKeycloakEndpointToken(r)

	// http://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users"
	s.userAPIFOrAdminURL, err = s.Config.GetKeycloakEndpointUsers(r)

	token, err := s.generateProtectedAccessToken()
	assert.Nil(s.T(), err)
	require.NotNil(s.T(), token)
	s.protectedAccessToken = *token
}

func (s *ProfileUserBlackBoxTest) TearDownTest() {
	//s.clean()
}

func (s *ProfileUserBlackBoxTest) generateProtectedAccessToken() (*string, error) {
	clientID := s.Config.GetKeycloakClientID()
	clientSecret := s.Config.GetKeycloakSecret()
	token, err := auth.GetProtectedAPIToken(context.Background(), s.tokenEndpoint, clientID, clientSecret)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), token)

	return &token, err
}

func (s *ProfileUserBlackBoxTest) TestPATGenerated() {
	assert.NotEmpty(s.T(), s.protectedAccessToken)
}

func (s *ProfileUserBlackBoxTest) TestKeycloakAddUser() {

	// UPDATE the user profile

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sbosetestusercreate" + uuid.NewV4().String()
	testEnabled := true
	testEmailVerified := true

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := login.KeytcloakUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testKeycloakUserProfileAttributes,
	}

	userURL := s.createUser(&testKeycloakUserData)

	// TODO: Handle error, check if there was actually a URL returned.
	userURLComponents := strings.Split(*userURL, "/")
	identityID := userURLComponents[len(userURLComponents)-1]
	idpName := "rhd"
	linkRequest := keycloakLink.KeycloakLinkIDPRequest{
		UserID:           &identityID,
		Username:         testKeycloakUserData.Username,
		IdentityProvider: &idpName,
	}

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	//"https://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users/" + identityID + "/federated-identity/rhd"
	linkURL, err := s.Config.GetKeycloakEndpointLinkIDP(r, identityID, idpName)
	require.Nil(s.T(), err)

	err = s.idpLinkService.Create(context.Background(), &linkRequest, s.protectedAccessToken, linkURL)
	require.Nil(s.T(), err)

}

func (s *ProfileUserBlackBoxTest) createUser(userProfile *login.KeytcloakUserRequest) *string {
	url, err := s.profileService.Create(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	return url
}
