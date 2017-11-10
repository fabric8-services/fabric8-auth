package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"

	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestToken(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestWhiteboxTokenSuite{})
}

type TestWhiteboxTokenSuite struct {
	suite.Suite
	config       *config.ConfigurationData
	privateKey   *rsa.PrivateKey
	tokenManager *tokenManager
}

func (s *TestWhiteboxTokenSuite) SetupSuite() {
	var err error
	s.config, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("failed to setup the configuration: %s", err.Error()))
	}
	s.tokenManager = newTestTokenManager()
}

func (s *TestWhiteboxTokenSuite) TearDownSuite() {
}

func newTestTokenManager() *tokenManager {
	rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.DefaultServiceAccountPrivateKey))
	if err != nil {
		panic(fmt.Errorf("failed to parse priviate key: %s", err.Error()))
	}
	serviceAccountKey := &PrivateKey{KeyID: "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs", Key: rsaServiceAccountKey}
	saPublicKey := &serviceAccountKey.Key.PublicKey

	return &tokenManager{
		publicKeysMap:            map[string]*rsa.PublicKey{serviceAccountKey.KeyID: saPublicKey},
		publicKeys:               []*PublicKey{{KeyID: serviceAccountKey.KeyID, Key: saPublicKey}},
		serviceAccountPrivateKey: serviceAccountKey,
	}
}

func (s *TestWhiteboxTokenSuite) TestAuthServiceAccountGeneratedOK() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	tokenString, err := s.tokenManager.AuthServiceAccountToken(r)
	require.Nil(s.T(), err)

	s.checkServiceAccountToken(tokenString, AuthServiceAccountID, "fabric8-auth")
}

func (s *TestWhiteboxTokenSuite) TestServiceAccountGeneratedOK() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	saID := uuid.NewV4().String()
	tokenString, err := s.tokenManager.GenerateServiceAccountToken(r, saID, "test-token")
	require.Nil(s.T(), err)
	s.checkServiceAccountToken(tokenString, saID, "test-token")
}

func (s *TestWhiteboxTokenSuite) TestNotAServiceAccountFails() {
	ctx := createInvalidSAContext()
	assert.False(s.T(), IsServiceAccount(ctx))
	assert.False(s.T(), IsSpecificServiceAccount(ctx, "someName"))
}

func (s *TestWhiteboxTokenSuite) checkServiceAccountToken(rawToken string, saID string, saName string) {
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		if kid == nil {
			return nil, errors.New("There is no 'kid' header in the token")
		}
		if fmt.Sprintf("%s", kid) != s.tokenManager.serviceAccountPrivateKey.KeyID {
			return nil, errors.New(fmt.Sprintf("The key ID %s doesn't match the private key ID %s", kid, s.tokenManager.serviceAccountPrivateKey.KeyID))
		}
		key := s.tokenManager.PublicKey(fmt.Sprintf("%s", kid))
		if key == nil {
			return nil, errors.New(fmt.Sprintf("There is no public key with such ID: %s", kid))
		}
		return key, nil
	})
	require.Nil(s.T(), err)

	claims := token.Claims.(jwt.MapClaims)
	require.Equal(s.T(), saID, claims["sub"])
	require.Equal(s.T(), saName, claims["service_accountname"])
	require.Equal(s.T(), []interface{}{"uma_protection"}, claims["scopes"])
	jti, ok := claims["jti"].(string)
	require.True(s.T(), ok)
	_, err = uuid.FromString(jti)
	require.Nil(s.T(), err)
	require.NotEmpty(s.T(), claims["iat"])
	require.Equal(s.T(), "http://example.com", claims["iss"])

	ctx := goajwt.WithJWT(context.Background(), token)
	assert.True(s.T(), IsServiceAccount(ctx))
	assert.True(s.T(), IsSpecificServiceAccount(ctx, saName))
	assert.False(s.T(), IsSpecificServiceAccount(ctx, saName+"wrongName"))
}

func createInvalidSAContext() context.Context {
	claims := jwt.MapClaims{}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return goajwt.WithJWT(context.Background(), token)
}
