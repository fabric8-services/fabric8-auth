package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/client"
	jwtgoa "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var config = configurationData()
var TokenManager = newManager()

// EmbedTokenInContext generates a token and embed it into the context
func EmbedTokenInContext(sub, username string) (context.Context, string, error) {
	// Generate Token with an identity that doesn't exist in the database
	tokenString, err := GenerateToken(sub, username)
	if err != nil {
		return nil, "", err
	}

	extracted, err := TokenManager.Parse(context.Background(), tokenString)
	if err != nil {
		return nil, "", err
	}

	// Embed Token in the context
	ctx := jwtgoa.WithJWT(context.Background(), extracted)
	return ctx, tokenString, nil
}

// EmbedIdentityInContext generates a token for the given identity and embed it into the context along with token manager
func EmbedIdentityInContext(identity account.Identity) (context.Context, error) {
	ctx, _, err := EmbedTokenInContext(identity.ID.String(), identity.Username)
	if err != nil {
		return nil, err
	}
	ctx = ContextWithRequest(ctx)
	return tokencontext.ContextWithTokenManager(ctx, TokenManager), nil
}

// GenerateToken generates a JWT token and signs it using the default private key
func GenerateToken(identityID string, identityUsername string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims.(jwt.MapClaims)["uuid"] = identityID
	token.Claims.(jwt.MapClaims)["preferred_username"] = identityUsername
	token.Claims.(jwt.MapClaims)["sub"] = identityID
	token.Claims.(jwt.MapClaims)["email"] = identityUsername

	key, kid, err := privateKey()
	if err != nil {
		return "", errors.WithStack(err)
	}
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(key)

	if err != nil {
		return "", errors.WithStack(err)
	}
	return tokenStr, nil
}

// GenerateTokenWithClaims generates a JWT token with additional claims
func GenerateTokenWithClaims(claims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)

	token.Claims.(jwt.MapClaims)["uuid"] = uuid.NewV4().String()
	token.Claims.(jwt.MapClaims)["preferred_username"] = fmt.Sprintf("testUser-%s", uuid.NewV4().String())
	token.Claims.(jwt.MapClaims)["sub"] = uuid.NewV4().String()

	token.Claims.(jwt.MapClaims)["jti"] = uuid.NewV4().String()
	token.Claims.(jwt.MapClaims)["session_state"] = uuid.NewV4().String()
	token.Claims.(jwt.MapClaims)["iat"] = time.Now().Unix()
	token.Claims.(jwt.MapClaims)["exp"] = time.Now().Unix() + 60*60*24*30

	token.Claims.(jwt.MapClaims)["nbf"] = 0
	token.Claims.(jwt.MapClaims)["iss"] = "fabric8-auth"
	token.Claims.(jwt.MapClaims)["typ"] = "Bearer"

	token.Claims.(jwt.MapClaims)["approved"] = true
	token.Claims.(jwt.MapClaims)["name"] = "Test User"
	token.Claims.(jwt.MapClaims)["company"] = "Company Inc."
	token.Claims.(jwt.MapClaims)["given_name"] = "Test"
	token.Claims.(jwt.MapClaims)["family_name"] = "User"
	token.Claims.(jwt.MapClaims)["email"] = fmt.Sprintf("testuser+%s@email.com", uuid.NewV4().String())
	token.Claims.(jwt.MapClaims)["email_verified"] = true

	for key, value := range claims {
		token.Claims.(jwt.MapClaims)[key] = value
	}
	key, kid, err := privateKey()
	if err != nil {
		return "", errors.WithStack(err)
	}
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return tokenStr, nil
}

func GenerateAccessTokenWithClaims(claims map[string]interface{}) (string, error) {
	return GenerateTokenWithClaims(claims)
}

func GenerateRefreshTokenWithClaims(claims map[string]interface{}) (string, error) {
	claims["approved"] = nil
	claims["company"] = nil
	claims["email"] = nil
	claims["email_verified"] = nil
	claims["typ"] = "Refresh"
	claims["preferred_username"] = nil
	claims["name"] = nil
	return GenerateTokenWithClaims(claims)
}

func GenerateUserTokenForIdentity(ctx context.Context, identity account.Identity, offlineToken bool) (*oauth2.Token, error) {
	rw := httptest.NewRecorder()
	u := &url.URL{Host: "auth.openshift.io"}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	goaCtx := goa.NewContext(ctx, rw, req, url.Values{})
	return TokenManager.GenerateUserTokenForIdentity(goaCtx, identity, offlineToken)
}

// UpdateToken generates a new token based on the existing one with additional claims
func UpdateToken(tokenString string, claims map[string]interface{}) (string, error) {
	newToken := jwt.New(jwt.SigningMethodRS256)

	oldTokenClaims, err := TokenManager.ParseTokenWithMapClaims(context.Background(), tokenString)
	if err != nil {
		return "", err
	}
	for key, value := range oldTokenClaims {
		switch value.(type) {
		case float64:
			number, err := token.NumberToInt(value)
			if err != nil {
				return "", err
			}
			newToken.Claims.(jwt.MapClaims)[key] = number
		default:
			newToken.Claims.(jwt.MapClaims)[key] = value
		}
	}
	for key, value := range claims {
		newToken.Claims.(jwt.MapClaims)[key] = value
	}
	key, kid, err := privateKey()
	if err != nil {
		return "", errors.WithStack(err)
	}
	newToken.Header["kid"] = kid
	tokenStr, err := newToken.SignedString(key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return tokenStr, nil
}

func ContextWithRequest(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	u := &url.URL{
		Scheme: "https",
		Host:   "auth.openshift.io",
	}
	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}
	return goa.NewContext(goa.WithAction(ctx, "Test"), rw, req, url.Values{})
}

func ContextWithTokenAndRequestID(t *testing.T) (context.Context, string, string) {
	ctx, ctxToken, err := EmbedTokenInContext(uuid.NewV4().String(), uuid.NewV4().String())
	ctx = tokencontext.ContextWithTokenManager(ctx, TokenManager)
	require.NoError(t, err)

	reqID := uuid.NewV4().String()
	ctx = client.SetContextRequestID(ctx, reqID)

	return ctx, ctxToken, reqID
}

func ContextWithTokenManager() context.Context {
	return tokencontext.ContextWithTokenManager(context.Background(), TokenManager)
}

func configurationData() *configuration.ConfigurationData {
	config, err := configuration.GetConfigurationData()
	if err != nil {
		panic("failed to load configuration: " + err.Error())
	}
	return config
}

func newManager() token.Manager {
	tm, err := token.NewManager(config)
	if err != nil {
		panic("failed to create token manager: " + err.Error())
	}
	return tm
}

func privateKey() (*rsa.PrivateKey, string, error) {
	key, kid := config.GetUserAccountPrivateKey()
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	return pk, kid, err
}

// EqualAccessTokens returns an error if the tokens are not equal
func EqualAccessTokens(ctx context.Context, expectedToken, actualToken string) error {
	expectedParsed, err := TokenManager.ParseToken(ctx, expectedToken)
	if err != nil {
		return err
	}
	expectedClaims, err := TokenManager.ParseTokenWithMapClaims(ctx, expectedToken)
	if err != nil {
		return err
	}
	actualClaims, err := TokenManager.ParseTokenWithMapClaims(ctx, actualToken)
	if err != nil {
		return err
	}
	actualParsed, err := TokenManager.ParseToken(ctx, actualToken)
	if err != nil {
		return err
	}

	err = equalTokenClaim("typ", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	if expectedParsed.Approved != actualParsed.Approved {
		return errors.Errorf("'approved' claims are not equal. Expected: %v. Actual: %v", expectedParsed.Approved, actualParsed.Approved)
	}
	err = equalTokenClaim("email", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	err = equalTokenClaim("email_verified", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	err = equalTokenClaim("preferred_username", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	err = equalTokenClaim("name", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	return equalTokenClaim("sub", expectedClaims, actualClaims)
}

// EqualRefreshTokens returns an error if the refresh tokens are not equal
func EqualRefreshTokens(ctx context.Context, expectedToken, actualToken string) error {
	expectedClaims, err := TokenManager.ParseTokenWithMapClaims(ctx, expectedToken)
	if err != nil {
		return err
	}
	actualClaims, err := TokenManager.ParseTokenWithMapClaims(ctx, actualToken)
	if err != nil {
		return err
	}

	err = equalTokenClaim("typ", expectedClaims, actualClaims)
	if err != nil {
		return err
	}
	return equalTokenClaim("sub", expectedClaims, actualClaims)

	return nil
}

func equalTokenClaim(claimName string, expectedToken, actualToken jwt.MapClaims) error {
	if expectedToken[claimName] != actualToken[claimName] {
		return errors.Errorf("'%s' claims are not equal. Expected: %v. Actual: %v", claimName, expectedToken[claimName], actualToken[claimName])
	}
	return nil
}
