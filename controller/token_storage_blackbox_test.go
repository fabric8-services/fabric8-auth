package controller_test

import (
	"context"
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
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenStorageREST struct {
	gormtestsupport.DBTestSuite
	identityRepository              account.IdentityRepository
	userRepository                  account.UserRepository
	externalProviderTokenRepository provider.ExternalProviderTokenRepository

	db    *gormapplication.GormDB
	clean func()
}

func TestRunTokenStorageREST(t *testing.T) {
	suite.Run(t, &TestTokenStorageREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestTokenStorageREST) SetupTest() {
	rest.externalProviderTokenRepository = provider.NewExternalProviderTokenRepository(rest.DB)
	rest.userRepository = account.NewUserRepository(rest.DB)
	rest.identityRepository = account.NewIdentityRepository(rest.DB)
	rest.externalProviderTokenRepository = provider.NewExternalProviderTokenRepository(rest.DB)
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
	return svc, NewTokenController(svc, loginService, loginService.TokenManager, rest.Configuration, rest.identityRepository, rest.externalProviderTokenRepository)
}

func (rest *TestTokenStorageREST) TestRetrieveExternalToken() {
	resource.Require(rest.T(), resource.Database)
	identity := rest.createRandomUserAndIdentityForStorage()
	service, controller := rest.SecuredControllerWithIdentity(identity)

	providerTypeID := provider.GithubProvider.ID
	defaultScope := provider.GithubProvider.DefaultScope

	externalProviderToken := provider.ExternalProviderToken{
		ProviderID: providerTypeID,
		Token:      uuid.NewV4().String(),
		Scope:      defaultScope,
		IdentityID: identity.ID,
	}
	err := rest.externalProviderTokenRepository.Create(service.Context, &externalProviderToken)
	require.Nil(rest.T(), err)

	_, result := test.RetrieveTokenOK(rest.T(), service.Context, service, controller, "http://github.com/a/b", nil)
	rest.validateTokenResponse(externalProviderToken, result, provider.GithubProvider.Type)
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

	profile := "foobarforupdate.com"
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

func (rest *TestTokenStorageREST) validateTokenResponse(externalProviderToken provider.ExternalProviderToken, result *app.ExternalProviderToken, providerType string) {
	require.NotNil(rest.T(), result)
	require.NotNil(rest.T(), result.Data)
	require.NotNil(rest.T(), result.Data.Attributes)
	require.Equal(rest.T(), externalProviderToken.Token, result.Data.Attributes.Token)
	require.Equal(rest.T(), externalProviderToken.Scope, result.Data.Attributes.Scope)
	require.Equal(rest.T(), externalProviderToken.IdentityID.String(), result.Data.Attributes.IdentityID)
	require.Equal(rest.T(), providerType, result.Data.Attributes.ExternalProviderType)
}
