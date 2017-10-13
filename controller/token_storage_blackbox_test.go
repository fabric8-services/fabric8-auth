package controller_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/keycloak"
	"github.com/fabric8-services/fabric8-auth/token/link"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenStorageREST struct {
	gormtestsupport.DBTestSuite
	db                      *gormapplication.GormDB
	identityRepository      account.IdentityRepository
	externalTokenRepository provider.ExternalTokenRepository
	userRepository          account.UserRepository

	Configuration         *configuration.ConfigurationData
	providerConfigFactory link.OauthProviderFactory
	clean                 func()
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.DBTestSuite.SetupSuite()
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalTokenRepository = provider.NewExternalTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)

	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	rest.Configuration = config
	rest.providerConfigFactory = link.NewOauthProviderFactory(config, rest.db)
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
	return svc, NewTokenController(svc, rest.db, loginService, &DummyLinkService{}, rest.providerConfigFactory, loginService.TokenManager, newMockKeycloakExternalTokenServiceClient(), rest.Configuration)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalToken() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "http://github.com/a/b", nil)
	//rest.validateTokenResponse(externalToken, result, "http://github.com/a/b")

}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenUnauthorized() {
	resource.Require(rest.T(), resource.Database)
	identity := testsupport.TestIdentity
	service, controller := rest.SecuredControllerWithIdentity(identity)
	test.RetrieveTokenUnauthorized(rest.T(), service.Context, service, controller, "http://github.com/a/b", nil)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalTokenBadRequest() {
	resource.Require(rest.T(), resource.Database)
	identity := testsupport.TestIdentity
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

type mockKeycloakExternalTokenServiceClient struct {
}

func newMockKeycloakExternalTokenServiceClient() mockKeycloakExternalTokenServiceClient {
	return mockKeycloakExternalTokenServiceClient{}
}

func (mockKeycloakExternalTokenServiceClient) Get(ctx context.Context, accessToken string, keycloakExternalTokenURL string) (*keycloak.KeycloakExternalTokenResponse, error) {
	return &keycloak.KeycloakExternalTokenResponse{
		AccessToken: "1234",
		Scope:       "default-gh",
		TokenType:   "bearer",
	}, nil
}
