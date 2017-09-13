package token_test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"testing"

	"golang.org/x/oauth2"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/dgrijalva/jwt-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestToken(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestTokenSuite{})
}

type TestTokenSuite struct {
	suite.Suite
	config       *configuration.ConfigurationData
	privateKey   *rsa.PrivateKey
	tokenManager token.Manager
}

func (s *TestTokenSuite) SetupSuite() {
	resource.Require(s.T(), resource.UnitTest)
	var err error
	s.config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	s.privateKey = testtoken.PrivateKey()
	s.tokenManager = testtoken.NewManager()
}

func (s *TestTokenSuite) TearDownSuite() {
}

func (s *TestTokenSuite) TestValidOAuthAccessToken() {
	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: "testuser",
	}
	generatedToken, err := testtoken.GenerateToken(identity.ID.String(), identity.Username, s.privateKey)
	assert.Nil(s.T(), err)
	accessToken := &oauth2.Token{
		AccessToken: generatedToken,
		TokenType:   "Bearer",
	}

	claims, err := s.tokenManager.ParseToken(context.Background(), accessToken.AccessToken)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), identity.ID.String(), claims.Subject)
	assert.Equal(s.T(), identity.Username, claims.Username)
}

func (s *TestTokenSuite) TestInvalidOAuthAccessToken() {
	invalidAccessToken := "7423742yuuiy-INVALID-73842342389h"

	accessToken := &oauth2.Token{
		AccessToken: invalidAccessToken,
		TokenType:   "Bearer",
	}

	_, err := s.tokenManager.ParseToken(context.Background(), accessToken.AccessToken)
	assert.NotNil(s.T(), err)
}

func (s *TestTokenSuite) TestCheckClaimsOK() {
	claims := &token.TokenClaims{
		Email:    "somemail@domain.com",
		Username: "testuser",
	}
	claims.Subject = uuid.NewV4().String()

	assert.Nil(s.T(), token.CheckClaims(claims))
}

func (s *TestTokenSuite) TestCheckClaimsFails() {
	claimsNoEmail := &token.TokenClaims{
		Username: "testuser",
	}
	claimsNoEmail.Subject = uuid.NewV4().String()
	assert.NotNil(s.T(), token.CheckClaims(claimsNoEmail))

	claimsNoUsername := &token.TokenClaims{
		Email: "somemail@domain.com",
	}
	claimsNoUsername.Subject = uuid.NewV4().String()
	assert.NotNil(s.T(), token.CheckClaims(claimsNoUsername))

	claimsNoSubject := &token.TokenClaims{
		Email:    "somemail@domain.com",
		Username: "testuser",
	}
	assert.NotNil(s.T(), token.CheckClaims(claimsNoSubject))
}

func (s *TestTokenSuite) TestLocateTokenInContex() {
	id := uuid.NewV4()

	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Claims.(jwt.MapClaims)["sub"] = id.String()
	ctx := goajwt.WithJWT(context.Background(), tk)

	foundId, err := s.tokenManager.Locate(ctx)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), id, foundId, "ID in created context not equal")
}

func (s *TestTokenSuite) TestLocateMissingTokenInContext() {
	ctx := context.Background()

	_, err := s.tokenManager.Locate(ctx)
	if err == nil {
		s.T().Error("Should have returned error on missing token in contex", err)
	}
}

func (s *TestTokenSuite) TestLocateMissingUUIDInTokenInContext() {
	tk := jwt.New(jwt.SigningMethodRS256)
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := s.tokenManager.Locate(ctx)
	require.NotNil(s.T(), err)
}

func (s *TestTokenSuite) TestLocateInvalidUUIDInTokenInContext() {
	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Claims.(jwt.MapClaims)["sub"] = "131"
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := s.tokenManager.Locate(ctx)
	require.NotNil(s.T(), err)
}
