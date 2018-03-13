package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/login/tokencontext"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/dgrijalva/jwt-go"
	jwtgoa "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

var config = configurationData()
var TokenManager = newManager()

// EmbedTokenInContext generates a token and embed it into the context
func EmbedTokenInContext(sub, username string) (context.Context, error) {
	// Generate Token with an identity that doesn't exist in the database
	tokenString, err := GenerateToken(sub, username)
	if err != nil {
		return nil, err
	}

	extracted, err := TokenManager.Parse(context.Background(), tokenString)
	if err != nil {
		return nil, err
	}

	// Embed Token in the context
	ctx := jwtgoa.WithJWT(context.Background(), extracted)
	return ctx, nil
}

// EmbedIdentityInContext generates a token for the given identity and embed it into the context along with token manager
func EmbedIdentityInContext(identity account.Identity) (context.Context, error) {
	ctx, err := EmbedTokenInContext(identity.ID.String(), identity.Username)
	if err != nil {
		return nil, err
	}
	return tokencontext.ContextWithTokenManager(ctx, TokenManager), nil
}

// GenerateToken generates a JWT token and signs it using the default private key
func GenerateToken(identityID string, identityUsername string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims.(jwt.MapClaims)["uuid"] = identityID
	token.Claims.(jwt.MapClaims)["preferred_username"] = identityUsername
	token.Claims.(jwt.MapClaims)["sub"] = identityID

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
