package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenStorageREST struct {
	gormtestsupport.DBTestSuite
	identityRepository      account.IdentityRepository
	userRepository          account.UserRepository
	externalTokenRepository provider.ExternalTokenRepository

	db    *gormapplication.GormDB
	clean func()
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.externalTokenRepository = provider.NewExternalTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalTokenRepository = provider.NewExternalTokenRepository(rest.DB)
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
}

func (rest *TestTokenStorageREST) TearDownTest() {
	rest.clean()
}

func (rest *TestTokenStorageREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, &TokenController{Controller: svc.NewController("token"), Auth: TestLoginService{}, Configuration: rest.Configuration}
}

func (rest *TestTokenStorageREST) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.db, rest.Configuration)

	svc := testsupport.ServiceAsUser("Token-Service", identity)
	return svc, NewTokenController(svc, loginService, loginService.TokenManager, rest.Configuration, rest.identityRepository, rest.externalTokenRepository)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalToken() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)

	providerTypeID := provider.GithubProvider.ID
	defaultScope := provider.GithubProvider.DefaultScope

	externalToken := provider.ExternalToken{
		ProviderID: providerTypeID,
		Token:      uuid.NewV4().String(),
		Scope:      defaultScope,
		IdentityID: identity.ID,
	}
	err := rest.externalTokenRepository.Create(service.Context, &externalToken)
	require.Nil(rest.T(), err)

	_, result := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "http://github.com/a/b", nil)
	rest.validateTokenResponse(externalToken, result, "http://github.com/a/b")

}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnAuthorized() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)

	providerTypeID := provider.GithubProvider.ID
	providerString := provider.GithubProvider.Type
	defaultScope := provider.GithubProvider.DefaultScope

	externalToken := provider.ExternalToken{
		ProviderID: providerTypeID,
		Token:      uuid.NewV4().String(),
		Scope:      defaultScope,
		IdentityID: identity.ID,
	}
	err := rest.externalTokenRepository.Create(service.Context, &externalToken)
	require.Nil(rest.T(), err)

	identity = rest.createRandomUserAndIdentityForStorage()
	service, controller = rest.SecuredControllerWithIdentity(identity)

	// This part needs fixing - there's no referrer
	errorResponse := fmt.Sprintf("LINK provider=%s, url=%s, description=”Link account”", providerString, "http:///api/link?redirect=&scope="+defaultScope)

	response, _ := test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "http://github.com/a/b", nil)
	require.Contains(rest.T(), response.Header().Get("WWW-Authenticate"), errorResponse)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnAuthorizedDummyRequest() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)

	providerTypeID := provider.GithubProvider.ID
	//providerString := provider.GithubProvider.Type
	defaultScope := provider.GithubProvider.DefaultScope

	externalToken := provider.ExternalToken{
		ProviderID: providerTypeID,
		Token:      uuid.NewV4().String(),
		Scope:      defaultScope,
		IdentityID: identity.ID,
	}
	err := rest.externalTokenRepository.Create(service.Context, &externalToken)
	require.Nil(rest.T(), err)

	identity = rest.createRandomUserAndIdentityForStorage()
	service, controller = rest.SecuredControllerWithIdentity(identity)

	rw := httptest.NewRecorder()
	u := &url.URL{
		Scheme: "https",
		Host:   "auth.localhost.io",
		Path:   fmt.Sprintf("/api/token"),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}

	referrerClientURL := "http://localhost.example.ui/home"
	req.Header.Add("referer", referrerClientURL)

	prms := url.Values{
		"for": {"http://github.com/sbose78"},
	}

	goaCtx := goa.NewContext(service.Context, rw, req, prms)
	tokenCtx, err := app.NewRetrieveTokenContext(goaCtx, req, goa.New("TokenService"))
	require.Nil(rest.T(), err)

	err = controller.Retrieve(tokenCtx)
	require.NotNil(rest.T(), err)
	exptectedHeaderValue := "LINK provider=github, url=https://auth.localhost.io/api/link?redirect=http://localhost.example.ui/home&scope=user:full, description=”Link account”"
	assert.Contains(rest.T(), rw.Header().Get("WWW-Authenticate"), exptectedHeaderValue)

}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnBadRequest() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenBadRequest(rest.T(), service.Context, service, controller, "", nil)
}

func (rest *TestTokenStorageREST) createRandomUserAndIdentityForStorage() account.Identity {

	user := account.User{
		Email:    uuid.NewV4().String() + "primaryForUpdat7e@example.com",
		FullName: "fullname",
		ImageURL: "someURLForUpdate",
		ID:       uuid.NewV4(),
		Company:  uuid.NewV4().String() + "company",
	}
	err := rest.userRepository.Create(context.Background(), &user)
	require.Nil(rest.T(), err)

	profile := "foobarforupdate.com" + uuid.NewV4().String()
	identity := account.Identity{
		Username:     "TestUpdateUserIntegration123" + uuid.NewV4().String(),
		ProviderType: "KC",
		ProfileURL:   &profile,
		User:         user,
		UserID:       account.NullUUID{UUID: user.ID, Valid: true},
	}
	err = rest.identityRepository.Create(context.Background(), &identity)
	require.Nil(rest.T(), err)
	return identity
}

func (rest *TestTokenStorageREST) validateTokenResponse(externalToken provider.ExternalToken, result *app.ExternalToken, providerType string) {
	require.NotNil(rest.T(), result)
	require.NotNil(rest.T(), result.Data)
	require.NotNil(rest.T(), result.Data.Attributes)
	require.Equal(rest.T(), externalToken.Token, result.Data.Attributes.Token)
	require.Equal(rest.T(), externalToken.Scope, result.Data.Attributes.Scope)
	require.Equal(rest.T(), externalToken.IdentityID.String(), result.Data.Attributes.IdentityID)
	require.Equal(rest.T(), providerType, result.Data.Attributes.For)
}
