package token_test

import (
	"context"
	"fmt"
	"testing"
	"time"

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
	config *configuration.ConfigurationData
}

func (s *TestTokenSuite) SetupSuite() {
	var err error
	s.config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func (s *TestTokenSuite) TearDownSuite() {
}

func (s *TestTokenSuite) TestValidOAuthAccessToken() {
	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: "testuser",
	}
	generatedToken, err := testtoken.GenerateToken(identity.ID.String(), identity.Username)
	assert.Nil(s.T(), err)

	claims, err := testtoken.TokenManager.ParseToken(context.Background(), generatedToken)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), identity.ID.String(), claims.Subject)
	assert.Equal(s.T(), identity.Username, claims.Username)

	jwtToken, err := testtoken.TokenManager.Parse(context.Background(), generatedToken)
	require.Nil(s.T(), err)

	s.checkClaim(jwtToken, "sub", identity.ID.String())
	s.checkClaim(jwtToken, "preferred_username", identity.Username)
}

func (s *TestTokenSuite) checkClaim(token *jwt.Token, claimName string, expectedValue string) {
	jwtClaims := token.Claims.(jwt.MapClaims)
	claim, ok := jwtClaims[claimName]
	require.True(s.T(), ok)
	assert.Equal(s.T(), expectedValue, claim)
}

func (s *TestTokenSuite) TestInvalidOAuthAccessTokenFails() {
	// Invalid token format
	s.checkInvalidToken("7423742yuuiy-INVALID-73842342389h")

	// Missing kid
	s.checkInvalidToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjgyYjI5Yy01MTczLTQyZDgtODE0NS1iNDVmYTFlMzUzOGIiLCJleHAiOjE1MTk2MDc5NTIsIm5iZiI6MCwiaWF0IjoxNTE3MDE1OTUyLCJpc3MiOiJ0ZXN0IiwiYXVkIjoiZmFicmljOC1vbmxpbmUtcGxhdGZvcm0iLCJzdWIiOiIyMzk4NDM5OC04NTVhLTQyZDYtYTdmZS05MzZiYjRlOTJhMGMiLCJ0eXAiOiJCZWFyZXIiLCJzZXNzaW9uX3N0YXRlIjoiZWFkYzA2NmMtMTIzNC00YTU2LTlmMzUtY2U3MDdiNTdhNGU5IiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sImFwcHJvdmVkIjp0cnVlLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlRlc3QiLCJjb21wYW55IjoiIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJnaXZlbl9uYW1lIjoiIiwiZmFtaWx5X25hbWUiOiIiLCJlbWFpbCI6InRAdGVzdC50In0.B1WIoalbVhhExZ1YEbRqXhGhi-WesUBaIGF22LP-Lz4")

	// Unknown kid
	s.checkInvalidToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd25raWQifQ.eyJqdGkiOiIwMjgyYjI5Yy01MTczLTQyZDgtODE0NS1iNDVmYTFlMzUzOGIiLCJleHAiOjE1MTk2MDc5NTIsIm5iZiI6MCwiaWF0IjoxNTE3MDE1OTUyLCJpc3MiOiJ0ZXN0IiwiYXVkIjoiZmFicmljOC1vbmxpbmUtcGxhdGZvcm0iLCJzdWIiOiIyMzk4NDM5OC04NTVhLTQyZDYtYTdmZS05MzZiYjRlOTJhMGMiLCJ0eXAiOiJCZWFyZXIiLCJzZXNzaW9uX3N0YXRlIjoiZWFkYzA2NmMtMTIzNC00YTU2LTlmMzUtY2U3MDdiNTdhNGU5IiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sImFwcHJvdmVkIjp0cnVlLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlRlc3QiLCJjb21wYW55IjoiIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJnaXZlbl9uYW1lIjoiIiwiZmFtaWx5X25hbWUiOiIiLCJlbWFpbCI6InRAdGVzdC5jb20ifQ.8JpAbRXtEQX0S-jkXNRDXsj1IuGbXKlCJmBTqc_18Y0")

	// Invalid signature
	s.checkInvalidToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJqdGkiOiIwMjgyYjI5Yy01MTczLTQyZDgtODE0NS1iNDVmYTFlMzUzOGIiLCJleHAiOjE1MTk2MDc5NTIsIm5iZiI6MCwiaWF0IjoxNTE3MDE1OTUyLCJpc3MiOiJ0ZXN0IiwiYXVkIjoiZmFicmljOC1vbmxpbmUtcGxhdGZvcm0iLCJzdWIiOiIyMzk4NDM5OC04NTVhLTQyZDYtYTdmZS05MzZiYjRlOTJhMGMiLCJ0eXAiOiJCZWFyZXIiLCJzZXNzaW9uX3N0YXRlIjoiZWFkYzA2NmMtMTIzNC00YTU2LTlmMzUtY2U3MDdiNTdhNGU5IiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sImFwcHJvdmVkIjp0cnVlLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlRlc3QiLCJjb21wYW55IjoiIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJnaXZlbl9uYW1lIjoiIiwiZmFtaWx5X25hbWUiOiIiLCJlbWFpbCI6InRAdGVzdC50In0.MC6kQwHTaevCOdEd3eqDIXrDB68Rtq1LRSJMluO4n6c")

	// Expired
	claims := make(map[string]interface{})
	claims["iat"] = time.Now().Unix() - 60*60*24*100
	claims["exp"] = time.Now().Unix() - 60*60*24*30
	generatedToken, err := testtoken.GenerateTokenWithClaims(claims)
	require.Nil(s.T(), err)
	s.checkInvalidToken(generatedToken)
}

func (s *TestTokenSuite) checkInvalidToken(token string) {
	_, err := testtoken.TokenManager.ParseToken(context.Background(), token)
	assert.NotNil(s.T(), err)
	_, err = testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), token)
	assert.NotNil(s.T(), err)
	_, err = testtoken.TokenManager.Parse(context.Background(), token)
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

	foundId, err := testtoken.TokenManager.Locate(ctx)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), id, foundId, "ID in created context not equal")
}

func (s *TestTokenSuite) TestLocateMissingTokenInContext() {
	ctx := context.Background()

	_, err := testtoken.TokenManager.Locate(ctx)
	if err == nil {
		s.T().Error("Should have returned error on missing token in contex", err)
	}
}

func (s *TestTokenSuite) TestLocateMissingUUIDInTokenInContext() {
	tk := jwt.New(jwt.SigningMethodRS256)
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := testtoken.TokenManager.Locate(ctx)
	require.NotNil(s.T(), err)
}

func (s *TestTokenSuite) TestLocateInvalidUUIDInTokenInContext() {
	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Claims.(jwt.MapClaims)["sub"] = "131"
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := testtoken.TokenManager.Locate(ctx)
	require.NotNil(s.T(), err)
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
