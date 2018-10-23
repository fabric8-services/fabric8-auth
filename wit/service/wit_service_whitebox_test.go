package service

import (
	"net/http"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/rest"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/wit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/fabric8-services/fabric8-auth/app"
	goauuid "github.com/goadesign/goa/uuid"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

func TestWIT(t *testing.T) {
	suite.Run(t, &TestWITSuite{})
}

type TestWITSuite struct {
	testsuite.UnitTestSuite
	ws        *witServiceImpl
	doer      *testsupport.DummyHttpDoer
	witConfig *witURLConfig
}

func (s *TestWITSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.witConfig = &witURLConfig{
		ConfigurationData: s.Config,
		witURL:            "https://wit",
	}
	s.ws = NewWITService(nil, s.witConfig).(*witServiceImpl)
	doer := testsupport.NewDummyHttpDoer()
	s.ws.doer = doer
	s.doer = doer
}

func (s *TestWITSuite) TestCreateWITUser() {
	ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	ctx = manager.ContextWithTokenManager(ctx, testtoken.TokenManager)

	saToken := testtoken.TokenManager.AuthServiceAccountToken()

	// test data
	userID := uuid.NewV4()
	testUser := account.User{
		EmailVerified: true,
		FullName:      "OSIO Test Developer",
		Email:         "osio-test-developer@email.com",
		Bio:           "Test Bio",
		Company:       "xyz",
		URL:           "xyz.io",
		ImageURL:      "bio.io",
		ID:            userID}

	testIdentity := account.Identity{
		User:                  testUser,
		Username:              "test",
		ProviderType:          account.DefaultIDP,
		RegistrationCompleted: true}
	identityId := uuid.NewV4().String()

	// Set up expected request
	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "POST", req.Method)
		assert.Equal(s.T(), fmt.Sprintf("https://wit/api/users/%s", identityId), req.URL.String())
		assert.Equal(s.T(), "Bearer "+saToken, req.Header.Get("Authorization"))
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))

		expectedBody := fmt.Sprintf("{\"data\":{\"attributes\":{\"bio\":\"Test Bio\",\"company\":\"xyz\",\"email\":\"osio-test-developer@email.com\",\"fullName\":\"OSIO Test Developer\",\"imageURL\":\"bio.io\",\"providerType\":\"kc\",\"url\":\"xyz.io\",\"userID\":\"%s\",\"username\":\"test\"},\"type\":\"identities\"}}\n", userID)
		assert.Equal(s.T(), expectedBody, rest.ReadBody(req.Body))
	}

	s.T().Run("should return space if client ok", func(t *testing.T) {
		err := s.ws.CreateUser(ctx, &testIdentity, identityId)
		require.NoError(s.T(), err)
	})

	s.T().Run("should fail to create user if client returned an error", func(t *testing.T) {
		s.doer.Client.Response = nil
		s.doer.Client.Error = errors.New("failed to create user in wit")
		err := s.ws.CreateUser(ctx, &testIdentity, identityId)
		require.Error(s.T(), err)
		assert.Equal(s.T(), "failed to create user in wit", err.Error())
	})

	s.T().Run("should fail to create user if client returned unexpected status", func(t *testing.T) {
		s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError, Status: "500"}
		s.doer.Client.Error = nil
		err := s.ws.CreateUser(ctx, &testIdentity, identityId)
		require.Error(s.T(), err)
		testsupport.AssertError(s.T(), err, errors.New(""), "unable to create user in WIT. Response status: 500. Response body: ")
	})
}

func (s *TestWITSuite) TestUpdateWITUser() {
	ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())
	ctx = manager.ContextWithTokenManager(ctx, testtoken.TokenManager)

	saToken := testtoken.TokenManager.AuthServiceAccountToken()

	// test data
	identityId := uuid.NewV4().String()
	newEmail := "TestUpdateUserOK-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserOK"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	newCompany := "updateCompany " + uuid.NewV4().String()

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}

	// Set up expected request
	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "PATCH", req.Method)
		assert.Equal(s.T(), fmt.Sprintf("https://wit/api/users/%s", identityId), req.URL.String())
		assert.Equal(s.T(), "Bearer "+saToken, req.Header.Get("Authorization"))
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))

		expectedBody := fmt.Sprintf("{\"data\":{\"attributes\":{\"bio\":\"new bio\",\"company\":\"%s\",\"contextInformation\":{\"count\":3,\"last_visited\":\"yesterday\",\"rate\":100,\"space\":\"3d6dab8d-f204-42e8-ab29-cdb1c93130ad\"},\"email\":\"%s\",\"fullName\":\"TestUpdateUserOK\",\"imageURL\":\"http://new.image.io/imageurl\",\"url\":\"http://new.profile.url/url\"},\"type\":\"identities\"}}\n", newCompany, newEmail)
		assert.Equal(s.T(), expectedBody, rest.ReadBody(req.Body))
	}

	updateUsersPayload := createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, &newCompany, nil, nil, contextInformation)

	s.T().Run("should update user if client ok", func(t *testing.T) {
		err := s.ws.UpdateUser(ctx, &updateUsersPayload, identityId)
		require.NoError(t, err)
	})

	s.T().Run("should fail to update user if client returned an error", func(t *testing.T) {
		s.doer.Client.Response = nil
		s.doer.Client.Error = errors.New("failed to update user in wit")
		err := s.ws.UpdateUser(ctx, &updateUsersPayload, identityId)
		require.Error(t, err)
		assert.Equal(t, "failed to update user in wit", err.Error())

	})

	s.T().Run("should fail to update user if client returned unexpected status", func(t *testing.T) {
		s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError, Status: "500"}
		s.doer.Client.Error = nil
		err := s.ws.UpdateUser(ctx, &updateUsersPayload, identityId)
		require.Error(t, err)
		testsupport.AssertError(t, err, errors.New(""), "unable to update user in WIT. Response status: 500. Response body: ")

	})
}

func (s *TestWITSuite) TestGetSpace() {
	ctx, _, reqID := testtoken.ContextWithTokenAndRequestID(s.T())

	// test data
	spaceId := "00000000-0000-0000-0000-000000000002"
	testSpace, e := getSpace(spaceId, "00000000-0000-0000-0000-000000000004", "My Test Space", "My space description")
	assert.Nil(s.T(), e)

	s.doer.Client.Error = nil
	json, e := ioutil.ReadFile("../../test/data/space.json")
	assert.Nil(s.T(), e)

	body := ioutil.NopCloser(bytes.NewBuffer(json))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "GET", req.Method)
		assert.Equal(s.T(), fmt.Sprintf("https://wit/api/spaces/%s", spaceId), req.URL.String())
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))
	}

	s.T().Run("should return space if client ok", func(t *testing.T) {
		space, err := s.ws.GetSpace(ctx, spaceId)
		require.NoError(t, err)
		require.Equal(t, space, testSpace)
	})

	s.T().Run("should fail to get space if client returned an error", func(t *testing.T) {
		s.doer.Client.Response = nil
		s.doer.Client.Error = errors.New("failed to get space from wit")
		_, err := s.ws.GetSpace(ctx, spaceId)
		require.Error(t, err)
		assert.Equal(t, "failed to get space from wit", err.Error())
	})

	s.T().Run("should fail to get space if client returned unexpected status", func(t *testing.T) {
		s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError, Status: "500"}
		s.doer.Client.Error = nil
		_, err := s.ws.GetSpace(ctx, spaceId)
		require.Error(t, err)
		testsupport.AssertError(s.T(), err, errors.New(""), "unable to get space from WIT. Response status: 500. Response body: ")
	})
}

func (s *TestWITSuite) TestDefaultDoer() {
	ts := NewWITService(nil, s.witConfig).(*witServiceImpl)
	assert.Equal(s.T(), ts.config, s.witConfig)
	assert.Equal(s.T(), ts.doer, rest.DefaultHttpDoer())
}

type witURLConfig struct {
	*configuration.ConfigurationData
	witURL string
}

func (c *witURLConfig) GetWITURL() (string, error) {
	return c.witURL, nil
}

func (s *TestWITSuite) TestCreateClientWithServiceAccountToken() {
	// create a context
	ctx := tokentestsupport.ContextWithTokenManager()
	manager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := manager.AuthServiceAccountToken()

	// create the client
	cl, err := s.ws.createClientWithContextSigner(ctx)
	require.NoError(s.T(), err)

	// create a request
	req, err := http.NewRequest("GET", "http://example.com", nil)

	// sign the request with that client
	cl.JWTSigner.Sign(req)

	authHeader := req.Header.Get("Authorization")
	require.NotEmpty(s.T(), authHeader)
	require.Equal(s.T(), "Bearer "+saToken, authHeader)

}

func createUpdateUsersPayload(email, fullName, bio, imageURL, profileURL, company, username *string, registrationCompleted *bool, contextInformation map[string]interface{}) app.UpdateUsersPayload {
	return app.UpdateUsersPayload{
		Data: &app.UpdateUserData{
			Type: "identities",
			Attributes: &app.UpdateIdentityDataAttributes{
				Email:                 email,
				FullName:              fullName,
				Bio:                   bio,
				ImageURL:              imageURL,
				URL:                   profileURL,
				Company:               company,
				ContextInformation:    contextInformation,
				Username:              username,
				RegistrationCompleted: registrationCompleted,
			},
		},
	}
}

func getSpace(spaceId, ownerId, name, desc string) (*wit.Space, error) {
	sId, e := goauuid.FromString(spaceId)
	if e != nil {
		return nil, e
	}

	oId, e := goauuid.FromString(ownerId)
	if e != nil {
		return nil, e
	}

	return &wit.Space{sId, oId, name, desc}, nil
}
