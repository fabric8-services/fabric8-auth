package token_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/repository"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/errors"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

func TestToken(t *testing.T) {
	suite.Run(t, &TestTokenSuite{})
}

type TestTokenSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestTokenSuite) TestGenerateUserTokenForIdentity() {
	s.checkGenerateUserTokenForIdentity(false)
	s.checkGenerateUserTokenForIdentity(true) // Offline token
}

func (s *TestTokenSuite) checkGenerateUserTokenForIdentity(offlineToken bool) {
	token, identity, ctx := s.generateToken(offlineToken)
	s.assertGeneratedToken(token, identity, offlineToken)

	// With verified email
	identity.User.EmailVerified = true
	token, err := testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity, offlineToken)
	require.NoError(s.T(), err)
	s.assertGeneratedToken(token, identity, offlineToken)
}

func (s *TestTokenSuite) assertGeneratedToken(generatedToken *oauth2.Token, identity repository.Identity, offlineToken bool) {
	require.NotNil(s.T(), generatedToken)
	assert.Equal(s.T(), "bearer", generatedToken.TokenType)

	assert.True(s.T(), generatedToken.Valid())

	// Extra
	s.assertInt(30*24*60*60, generatedToken.Extra("expires_in"))
	s.assertInt(30*24*60*60, generatedToken.Extra("refresh_expires_in"))
	s.assertInt(0, generatedToken.Extra("not_before_policy"))

	// Access token

	accessToken, err := testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), generatedToken.AccessToken)
	require.NoError(s.T(), err)

	// Headers
	s.assertHeaders(generatedToken.AccessToken)

	// Claims
	s.assertJti(accessToken)
	iat := s.assertIat(accessToken)
	s.assertExpiresIn(accessToken["exp"])
	s.assertIntClaim(accessToken, "nbf", 0)
	s.assertClaim(accessToken, "iss", "https://auth.openshift.io")
	s.assertClaim(accessToken, "aud", "https://openshift.io")
	s.assertClaim(accessToken, "typ", "Bearer")
	s.assertClaim(accessToken, "auth_time", iat)
	s.assertClaim(accessToken, "approved", !identity.User.Deprovisioned)
	s.assertClaim(accessToken, "sub", identity.ID.String())
	s.assertClaim(accessToken, "email", identity.User.Email)
	s.assertClaim(accessToken, "email_verified", identity.User.EmailVerified)
	s.assertClaim(accessToken, "preferred_username", identity.Username)

	firstName, lastName := account.SplitFullName(identity.User.FullName)
	s.assertClaim(accessToken, "given_name", firstName)
	s.assertClaim(accessToken, "family_name", lastName)

	s.assertClaim(accessToken, "allowed-origins", []interface{}{
		"https://auth.openshift.io",
		"https://openshift.io",
	})

	// Refresh token

	refreshToken, err := testtoken.TokenManager.ParseTokenWithMapClaims(context.Background(), generatedToken.RefreshToken)
	require.NoError(s.T(), err)

	// Headers
	s.assertHeaders(generatedToken.RefreshToken)

	// Claims
	s.assertJti(refreshToken)
	s.assertIat(refreshToken)
	s.assertIntClaim(refreshToken, "nbf", 0)
	s.assertClaim(refreshToken, "iss", "https://auth.openshift.io")
	s.assertClaim(refreshToken, "aud", "https://openshift.io")
	if offlineToken {
		s.assertIntClaim(refreshToken, "exp", 0)
		s.assertClaim(refreshToken, "typ", "Offline")
	} else {
		s.assertExpiresIn(refreshToken["exp"])
		s.assertClaim(refreshToken, "typ", "Refresh")
	}
	s.assertIntClaim(refreshToken, "auth_time", 0)
	s.assertClaim(refreshToken, "sub", identity.ID.String())
}

func (s *TestTokenSuite) TestAddLoginRequiredHeader() {
	rw := httptest.NewRecorder()
	testtoken.TokenManager.AddLoginRequiredHeader(rw)

	s.checkLoginRequiredHeader(rw)

	rw = httptest.NewRecorder()
	rw.Header().Set("Access-Control-Expose-Headers", "somecustomvalue")
	testtoken.TokenManager.AddLoginRequiredHeader(rw)
	s.checkLoginRequiredHeader(rw)
}

func (s *TestTokenSuite) TestAddLoginRequiredHeaderToUnauthorizedError() {
	rw := httptest.NewRecorder()
	err := errors.NewInternalErrorFromString(context.Background(), "oopsie woopsie")

	testtoken.TokenManager.AddLoginRequiredHeaderToUnauthorizedError(err, rw)
	header := textproto.MIMEHeader(rw.Header())
	assert.NotContains(s.T(), header, "WWW-Authenticate")
	assert.NotContains(s.T(), header, "Access-Control-Expose-Headers")

	unthErr := errors.NewUnauthorizedError("oopsie woopsie")
	rw = httptest.NewRecorder()
	testtoken.TokenManager.AddLoginRequiredHeaderToUnauthorizedError(unthErr, rw)
	s.checkLoginRequiredHeader(rw)

	rw = httptest.NewRecorder()
	rw.Header().Set("Access-Control-Expose-Headers", "somecustomvalue")
	testtoken.TokenManager.AddLoginRequiredHeaderToUnauthorizedError(unthErr, rw)
	s.checkLoginRequiredHeader(rw)
}

func (s *TestTokenSuite) checkLoginRequiredHeader(rw http.ResponseWriter) {
	assert.Equal(s.T(), "LOGIN url=http://localhost/api/login, description=\"re-login is required\"", rw.Header().Get("WWW-Authenticate"))
	header := textproto.MIMEHeader(rw.Header())
	assert.Contains(s.T(), header["Access-Control-Expose-Headers"], "WWW-Authenticate")
}

func (s *TestTokenSuite) assertHeaders(tokenString string) {
	jwtToken, err := testtoken.TokenManager.Parse(context.Background(), tokenString)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "aUGv8mQA85jg4V1DU8Uk1W0uKsxn187KQONAGl6AMtc", jwtToken.Header["kid"])
	assert.Equal(s.T(), "RS256", jwtToken.Header["alg"])
	assert.Equal(s.T(), "JWT", jwtToken.Header["typ"])
}

func (s *TestTokenSuite) assertExpiresIn(actualValue interface{}) {
	require.NotNil(s.T(), actualValue)
	now := time.Now().Unix()
	expInt, err := token.NumberToInt(actualValue)
	require.NoError(s.T(), err)
	assert.True(s.T(), expInt >= now+30*24*60*60-60 && expInt < now+30*24*60*60+60, "expiration claim is not in 30 days (%d +/- 1m): %d", now+30*24*60*60, expInt) // Between 30 days from now and 30 days + 1 minute
}

func (s *TestTokenSuite) assertJti(claims jwt.MapClaims) {
	jti := claims["jti"]
	require.NotNil(s.T(), jti)
	require.IsType(s.T(), "", jti)
	_, err := uuid.FromString(jti.(string))
	assert.NoError(s.T(), err)
}

func (s *TestTokenSuite) assertIat(claims jwt.MapClaims) interface{} {
	iat := claims["iat"]
	require.NotNil(s.T(), iat)
	iatInt, err := token.NumberToInt(iat)
	require.NoError(s.T(), err)
	now := time.Now().Unix()
	assert.True(s.T(), iatInt <= now && iatInt > now-60, "'issued at' claim is not within one minute interval from now (%d): %d", now, iatInt) // Between now and 1 minute ago
	return iat
}

func (s *TestTokenSuite) assertClaim(claims jwt.MapClaims, claimName string, expectedValue interface{}) {
	clm := claims[claimName]
	require.NotNil(s.T(), clm)
	assert.Equal(s.T(), expectedValue, clm)
}

func (s *TestTokenSuite) assertIntClaim(claims jwt.MapClaims, claimName string, expectedValue interface{}) {
	clm := claims[claimName]
	require.NotNil(s.T(), clm)
	clmInt, err := token.NumberToInt(clm)
	expectedInt, err := token.NumberToInt(expectedValue)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), expectedInt, clmInt)
}

func (s *TestTokenSuite) assertInt(expectedValue, actualValue interface{}) {
	require.NotNil(s.T(), actualValue)
	actInt, err := token.NumberToInt(actualValue)
	require.NoError(s.T(), err)
	expInt, err := token.NumberToInt(expectedValue)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), actInt, expInt)
}

func (s *TestTokenSuite) TestConvertToken() {
	s.checkConvertToken(false)
	s.checkConvertToken(true) // Offline token
}

func (s *TestTokenSuite) checkConvertToken(offlineToken bool) {
	// Generate an oauth token first
	generatedToken, identity, _ := s.generateToken(offlineToken)

	// Now convert it to a token set
	tokenSet, err := testtoken.TokenManager.ConvertToken(*generatedToken)
	require.NoError(s.T(), err)

	// Convert the token set back to an oauth token
	token := testtoken.TokenManager.ConvertTokenSet(*tokenSet)
	require.NoError(s.T(), err)

	// Check the converted token
	s.assertGeneratedToken(token, identity, offlineToken)
}

func (s *TestTokenSuite) generateToken(offlineToken bool) (*oauth2.Token, repository.Identity, context.Context) {
	ctx := testtoken.ContextWithRequest(nil)
	user := repository.User{
		ID:       uuid.NewV4(),
		Email:    uuid.NewV4().String(),
		FullName: uuid.NewV4().String(),
		Cluster:  uuid.NewV4().String(),
	}
	identity := repository.Identity{
		ID:       uuid.NewV4(),
		User:     user,
		Username: uuid.NewV4().String(),
	}
	token, err := testtoken.TokenManager.GenerateUserTokenForIdentity(ctx, identity, offlineToken)
	require.NoError(s.T(), err)

	return token, identity, ctx
}

func (s *TestTokenSuite) TestValidOAuthAccessToken() {
	identity := repository.Identity{
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

func (s *TestTokenSuite) TestAuthServiceAccountSigner() {
	ctx := tokencontext.ContextWithTokenManager(context.Background(), testtoken.TokenManager)
	signer, err := token.AuthServiceAccountSigner(ctx)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), signer)

	// Sign request
	req := &http.Request{Header: map[string][]string{}}
	err = signer.Sign(req)
	require.NoError(s.T(), err)

	// Request should have Auth SA token in Authorization header
	assert.Equal(s.T(), "Bearer "+testtoken.TokenManager.AuthServiceAccountToken(), req.Header.Get("Authorization"))
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
