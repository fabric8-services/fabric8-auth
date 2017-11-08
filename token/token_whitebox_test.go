package token

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"

	"github.com/dgrijalva/jwt-go"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/goadesign/goa"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
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
		panic(fmt.Errorf("failed to setup parse priviate key: %s", err.Error()))
	}
	serviceAccountKey := &PrivateKey{KeyID: "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs", Key: rsaServiceAccountKey}
	saPublicKey := &serviceAccountKey.Key.PublicKey

	return &tokenManager{
		publicKeysMap:            map[string]*rsa.PublicKey{serviceAccountKey.KeyID: saPublicKey},
		publicKeys:               []*PublicKey{{KeyID: serviceAccountKey.KeyID, Key: saPublicKey}},
		serviceAccountPrivateKey: serviceAccountKey,
	}
}

func (s *TestWhiteboxTokenSuite) TestAuthServiceAccount() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	tokenString, err := s.tokenManager.AuthServiceAccountToken(r)
	require.Nil(s.T(), err)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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
	require.Equal(s.T(), AuthServiceAccountID, claims["sub"])
	require.Equal(s.T(), "auth", claims["service_accountname"])
	require.Equal(s.T(), []interface{}{"uma_protection"}, claims["scopes"])
	jti, ok := claims["jti"].(string)
	require.True(s.T(), ok)
	_, err = uuid.FromString(jti)
	require.Nil(s.T(), err)
	require.NotEmpty(s.T(), claims["iat"])
	require.Equal(s.T(), "http://example.com", claims["iss"])
}
