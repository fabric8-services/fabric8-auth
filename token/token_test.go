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

	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/auth"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/url"
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

func (s *TestTokenSuite) TestEncodeTokenOK() {
	referrerURL, _ := url.Parse("https://example.domain.com")
	accessToken := "accessToken%@!/\\&?"
	refreshToken := "refreshToken%@!/\\&?"
	tokenType := "tokenType%@!/\\&?"
	expiresIn := 1800
	var refreshExpiresIn float64
	refreshExpiresIn = 2.59e6

	outhToken := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
	}
	extra := map[string]interface{}{
		"expires_in":         expiresIn,
		"refresh_expires_in": refreshExpiresIn,
	}
	err := token.EncodeToken(context.Background(), referrerURL, outhToken.WithExtra(extra))
	assert.Nil(s.T(), err)
	encoded := referrerURL.String()

	referrerURL, _ = url.Parse(encoded)
	values := referrerURL.Query()
	tJSON := values["token_json"]
	b := []byte(tJSON[0])
	tokenData := &auth.Token{}
	err = json.Unmarshal(b, tokenData)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), accessToken, *tokenData.AccessToken)
	assert.Equal(s.T(), refreshToken, *tokenData.RefreshToken)
	assert.Equal(s.T(), tokenType, *tokenData.TokenType)
	assert.Equal(s.T(), int64(expiresIn), *tokenData.ExpiresIn)
	assert.Equal(s.T(), int64(refreshExpiresIn), *tokenData.RefreshExpiresIn)
}

func (s *TestTokenSuite) TestInt32ToInt64OK() {
	var i32 int32
	i32 = 60
	i, err := token.NumberToInt(i32)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), int64(i32), i)
}

func (s *TestTokenSuite) TestInt64ToInt64OK() {
	var i64 int64
	i64 = 6000000000000000000
	i, err := token.NumberToInt(i64)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), i64, i)
}

func (s *TestTokenSuite) TestFloat32ToInt64OK() {
	var f32 float32
	f32 = 0.1e1
	i, err := token.NumberToInt(f32)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), int64(f32), i)
}

func (s *TestTokenSuite) TestFloat64ToInt64OK() {
	var f64 float64
	f64 = 0.1e10
	i, err := token.NumberToInt(f64)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), int64(f64), i)
}

func (s *TestTokenSuite) TestStringToInt64OK() {
	str := "2590000"
	i, err := token.NumberToInt(str)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), int64(2590000), i)
}
