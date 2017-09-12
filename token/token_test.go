package token_test

import (
	"crypto/rsa"
	"testing"

	"golang.org/x/oauth2"

	"context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	privateKey   *rsa.PrivateKey
	tokenManager token.Manager
)

func init() {
	privateKey = testtoken.PrivateKey()
	tokenManager = testtoken.NewManager()
}

func TestValidOAuthAccessToken(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	identity := account.Identity{
		ID:       uuid.NewV4(),
		Username: "testuser",
	}
	generatedToken, err := testtoken.GenerateToken(identity.ID.String(), identity.Username, privateKey)
	assert.Nil(t, err)
	accessToken := &oauth2.Token{
		AccessToken: generatedToken,
		TokenType:   "Bearer",
	}

	claims, err := tokenManager.ParseToken(context.Background(), accessToken.AccessToken)
	assert.Nil(t, err)
	assert.Equal(t, identity.ID.String(), claims.Subject)
	assert.Equal(t, identity.Username, claims.Username)
}

func TestInvalidOAuthAccessToken(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	invalidAccessToken := "7423742yuuiy-INVALID-73842342389h"

	accessToken := &oauth2.Token{
		AccessToken: invalidAccessToken,
		TokenType:   "Bearer",
	}

	_, err := tokenManager.ParseToken(context.Background(), accessToken.AccessToken)
	assert.NotNil(t, err)
}

func TestCheckClaimsOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	claims := &token.TokenClaims{
		Email:    "somemail@domain.com",
		Username: "testuser",
	}
	claims.Subject = uuid.NewV4().String()

	assert.Nil(t, token.CheckClaims(claims))
}

func TestCheckClaimsFails(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	claimsNoEmail := &token.TokenClaims{
		Username: "testuser",
	}
	claimsNoEmail.Subject = uuid.NewV4().String()
	assert.NotNil(t, token.CheckClaims(claimsNoEmail))

	claimsNoUsername := &token.TokenClaims{
		Email: "somemail@domain.com",
	}
	claimsNoUsername.Subject = uuid.NewV4().String()
	assert.NotNil(t, token.CheckClaims(claimsNoUsername))

	claimsNoSubject := &token.TokenClaims{
		Email:    "somemail@domain.com",
		Username: "testuser",
	}
	assert.NotNil(t, token.CheckClaims(claimsNoSubject))
}

func TestLocateTokenInContex(t *testing.T) {
	id := uuid.NewV4()

	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Claims.(jwt.MapClaims)["sub"] = id.String()
	ctx := goajwt.WithJWT(context.Background(), tk)

	foundId, err := tokenManager.Locate(ctx)
	require.Nil(t, err)
	assert.Equal(t, id, foundId, "ID in created context not equal")
}

func TestLocateMissingTokenInContext(t *testing.T) {
	ctx := context.Background()

	_, err := tokenManager.Locate(ctx)
	if err == nil {
		t.Error("Should have returned error on missing token in contex", err)
	}
}

func TestLocateMissingUUIDInTokenInContext(t *testing.T) {
	tk := jwt.New(jwt.SigningMethodRS256)
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := tokenManager.Locate(ctx)
	require.NotNil(t, err)
}

func TestLocateInvalidUUIDInTokenInContext(t *testing.T) {
	tk := jwt.New(jwt.SigningMethodRS256)
	tk.Claims.(jwt.MapClaims)["sub"] = "131"
	ctx := goajwt.WithJWT(context.Background(), tk)

	_, err := tokenManager.Locate(ctx)
	require.NotNil(t, err)
}
