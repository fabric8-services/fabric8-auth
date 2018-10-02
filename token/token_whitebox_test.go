package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"sync"
	"testing"

	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/dgrijalva/jwt-go"
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
	testsuite.UnitTestSuite
	privateKey   *rsa.PrivateKey
	tokenManager *tokenManager
}

func (s *TestWhiteboxTokenSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	m, err := NewManager(s.Config)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), m)
	tm, ok := m.(*tokenManager)
	require.True(s.T(), ok)
	s.tokenManager = tm
}

type authURLConfig struct {
	*config.ConfigurationData
	authURL string
}

func (c *authURLConfig) GetAuthServiceURL() string {
	return c.authURL
}

func (s *TestWhiteboxTokenSuite) tokenManagerWithAuthURL() (*tokenManager, string) {
	authURL := uuid.NewV4().String()
	m, err := NewManager(&authURLConfig{
		ConfigurationData: s.Config,
		authURL:           authURL,
	})
	require.NoError(s.T(), err)
	require.NotNil(s.T(), m)
	tm, ok := m.(*tokenManager)
	require.True(s.T(), ok)
	return tm, authURL
}

func (s *TestWhiteboxTokenSuite) TestDefaultManager() {
	// Init default manager OK
	s.assertDefaultManager()
	s.resetDefaultManager()
	s.assertDefaultManager()

	// Use broken configuration
	keyEnv := os.Getenv("AUTH_USERACCOUNT_PRIVATEKEY")
	defer func() {
		os.Setenv("AUTH_USERACCOUNT_PRIVATEKEY", keyEnv)
		s.resetDefaultManager()
	}()
	os.Setenv("AUTH_USERACCOUNT_PRIVATEKEY", "broken-key")
	s.resetDefaultManager()
	c, err := config.GetConfigurationData() // Broken config
	require.NoError(s.T(), err)
	_, err1 := DefaultManager(c)
	require.Error(s.T(), err1)

	// Default manager is not initialized second time
	os.Setenv("AUTH_USERACCOUNT_PRIVATEKEY", keyEnv)
	c, err = config.GetConfigurationData() // Good config
	require.NoError(s.T(), err)
	_, err2 := DefaultManager(c)
	require.Error(s.T(), err2)
	assert.Equal(s.T(), err1, err2)

	s.resetDefaultManager()
	manager1, err := DefaultManager(s.Config)
	require.NoError(s.T(), err)
	manager2, err := DefaultManager(s.Config)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), manager1, manager2)
	assert.Equal(s.T(), manager1, defaultManager)
	assert.NotNil(s.T(), defaultManager)
}

func (s *TestWhiteboxTokenSuite) resetDefaultManager() {
	defaultManager = nil
	defaultErr = nil
	defaultOnce = sync.Once{}
}

func (s *TestWhiteboxTokenSuite) assertDefaultManager() {
	manager, err := DefaultManager(s.Config)
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), manager)
	assert.Equal(s.T(), defaultManager, manager)
}

func (s *TestWhiteboxTokenSuite) TestAuthServiceAccountGeneratedOK() {
	m, authURL := s.tokenManagerWithAuthURL()
	tokenString := m.AuthServiceAccountToken()
	s.checkServiceAccountToken(tokenString, AuthServiceAccountID, "fabric8-auth", authURL)

}

func (s *TestWhiteboxTokenSuite) TestServiceAccountGeneratedOK() {
	saID := uuid.NewV4().String()
	m, authURL := s.tokenManagerWithAuthURL()
	tokenString, err := m.GenerateServiceAccountToken(saID, "test-token")
	require.Nil(s.T(), err)
	s.checkServiceAccountToken(tokenString, saID, "test-token", authURL)
}

func (s *TestWhiteboxTokenSuite) TestNotAServiceAccountFails() {
	ctx := createInvalidSAContext()
	assert.False(s.T(), IsSpecificServiceAccount(ctx, "someName"))
}

func (s *TestWhiteboxTokenSuite) TestIsServiceAccountFails() {
	ctx := createInvalidSAContext()
	assert.False(s.T(), IsServiceAccount(ctx))
}

func (s *TestWhiteboxTokenSuite) checkServiceAccountToken(rawToken, saID, saName, iss string) {
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
	require.Equal(s.T(), iss, claims["iss"])

	ctx := goajwt.WithJWT(context.Background(), token)
	assert.True(s.T(), IsSpecificServiceAccount(ctx, saName))
	assert.True(s.T(), IsSpecificServiceAccount(ctx, saName+"wrongName", saName))
	assert.True(s.T(), IsSpecificServiceAccount(ctx, saName, saName+"wrongName"))
	assert.False(s.T(), IsSpecificServiceAccount(ctx, saName+"wrongName"))
	assert.False(s.T(), IsSpecificServiceAccount(ctx, saName+"wrongName", saName+"wrongName"))
}

func createInvalidSAContext() context.Context {
	claims := jwt.MapClaims{}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return goajwt.WithJWT(context.Background(), token)
}

func (s *TestWhiteboxTokenSuite) TestPrivateKeysLoaded() {
	// One service account key, one user key, and one dev mode key
	require.Equal(s.T(), 3, len(s.tokenManager.PublicKeys()))

	// SA key
	_, serviceAccountKid := s.Config.GetServiceAccountPrivateKey()
	require.NotEqual(s.T(), "", serviceAccountKid)
	require.NotNil(s.T(), s.tokenManager.PublicKey(serviceAccountKid))

	// User key
	_, userAccountKid := s.Config.GetUserAccountPrivateKey()
	require.NotEqual(s.T(), "", userAccountKid)
	require.NotNil(s.T(), s.tokenManager.PublicKey(userAccountKid))

	// Check all arrays and maps
	require.Equal(s.T(), len(s.tokenManager.publicKeys), len(s.tokenManager.PublicKeys()))
	require.Equal(s.T(), len(s.tokenManager.publicKeys), len(s.tokenManager.publicKeysMap))
	for i, k := range s.tokenManager.publicKeys {
		require.NotEqual(s.T(), "", k.KeyID)
		require.NotNil(s.T(), s.tokenManager.PublicKey(k.KeyID))
		require.Equal(s.T(), s.tokenManager.PublicKeys()[i], k.Key)
	}

	// Check JWK and PEM formats
	jwKeys := s.tokenManager.JSONWebKeys()
	require.NotEmpty(s.T(), jwKeys.Keys)

	pemKeys := s.tokenManager.PemKeys()
	require.NotEmpty(s.T(), pemKeys.Keys)
}

func (s *TestWhiteboxTokenSuite) TestPrivateKeysLoadedFromEnvVars() {
	s.checkPrivateKeyLoaded("AUTH_SERVICEACCOUNT_PRIVATEKEY", config.DefaultServiceAccountPrivateKey, "AUTH_SERVICEACCOUNT_PRIVATEKEYID", "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs")
	s.checkPrivateKeyLoaded("AUTH_USERACCOUNT_PRIVATEKEY", config.DefaultUserAccountPrivateKey, "AUTH_USERACCOUNT_PRIVATEKEYID", "aUGv8mQA85jg4V1DU8Uk1W0uKsxn187KQONAGl6AMtc")
	s.checkPrivateKeyLoaded("AUTH_SERVICEACCOUNT_PRIVATEKEY_DEPRECATED", deprecatedServiceAccountPrivateKey, "AUTH_SERVICEACCOUNT_PRIVATEKEYID_DEPRECATED", "bMa8r5iGklldtlb23HE6DBAeIwD1SpmCTEwm2TqyUTo")
	s.checkPrivateKeyLoaded("AUTH_USERACCOUNT_PRIVATEKEY_DEPRECATED", deprecatedUserAccountPrivateKey, "AUTH_USERACCOUNT_PRIVATEKEYID_DEPRECATED", "ATXsLMBt9YD8ZgSqCq84PMWNVai_Q2LjIp-lAneSi4s")
}

func (s *TestWhiteboxTokenSuite) checkPrivateKeyLoaded(keyEnvVarName, keyEnvVarValue, kidEnvVarName, kidEnvVarValue string) {
	keyEnv := os.Getenv(keyEnvVarName)
	kidEnv := os.Getenv(kidEnvVarName)
	defer func() {
		os.Setenv(keyEnvVarName, keyEnv)
		os.Setenv(kidEnvVarName, kidEnv)
	}()

	os.Setenv(keyEnvVarName, keyEnvVarValue)
	os.Setenv(kidEnvVarName, kidEnvVarValue)
	c, err := config.GetConfigurationData()
	require.NoError(s.T(), err)

	m, err := NewManager(c)
	require.NoError(s.T(), err)
	tm, ok := m.(*tokenManager)
	require.True(s.T(), ok)

	publicKey := tm.PublicKey(kidEnvVarValue)
	require.NotNil(s.T(), publicKey)

	rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(keyEnvVarValue))
	require.NoError(s.T(), err)
	require.Equal(s.T(), rsaServiceAccountKey.PublicKey, *publicKey)
}

func (s *TestWhiteboxTokenSuite) TestAuthServiceAccount() {
	tokenString := s.tokenManager.AuthServiceAccountToken()

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
	require.Equal(s.T(), "fabric8-auth", claims["service_accountname"])
	require.Equal(s.T(), []interface{}{"uma_protection"}, claims["scopes"])
	jti, ok := claims["jti"].(string)
	require.True(s.T(), ok)
	_, err = uuid.FromString(jti)
	require.Nil(s.T(), err)
	require.NotEmpty(s.T(), claims["iat"])
	require.Equal(s.T(), "http://localhost", claims["iss"])
}

const (
	deprecatedServiceAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAgYUCOars5k/zvFcm+GkLCviNftWWtXiva0Sp+mKwTRUpTw6+
B6Fz8gPv2WbmcKFi02YiEETDKx5uNkJixMj0ujxYh7C8c0uAvcdEPVIlgcaP8mnV
48my3Br278uhP2wsw51K/nehE829tRRpguMNQtjqqZerHqdEkFWAcRgsrSJVt2vP
ojgIJKMd0F+kYpvhHUpgIhwXL6iaTpyo7nVyE/T/6UENpe5PRo/Yszg+/dgkPJG7
RVLboNMsTiCzfTIdMlllrBR5BhBz6JXA/9mbNBfnB02j1oKuwV3jq9PhaSeprcmL
CZUuxclj4Au7oDuwrp7MfwcAlr5kd2L6nmPUEQIDAQABAoIBABaf3Vuld+xjWvgz
YSNTdhJciJr3RHQ+uKXMQMT0KEfOwoCE2r0Kfu5vsZ4QU4CpMFItLRYabN1DW40u
24H0eItvrydEwCaDseF0xX7QsqyQuuRliG9Z9FxueWQ59djWVJt3Bnqc+w4yikjv
X971OoPK0HL/g2y/W0K7LMyUpHk5noNH2s0G9qf4FHIo1Lwfpe9hIvs4CZxtRqO9
RsRDRoJEF6vFEd+qkNsJNwXynXap9SA1KTh2u1m1rVyDypsP+icHspRgeN2qTygp
i+z8c8eWl7KxE80GvepiAuGlNyR/udrDEYkPkIfqRnmJbsdwX0KieO1+RsDqfg4G
ZKTDMWECgYEAvfBMew1RFsQ+ifg3DmmHd/DwB++X10nJ+c3d8Mf8GWxxlMWzthRI
tEyAvd5ZcbIidHvDDeyBcxFSZvuaa2bzzNgbXiqZWQ4oQJCmGBQ9szCKudRaBIVZ
2aUe+AH5yGRC5D40hr4gCUcTEDYlYFZxrIjf6xvpxF4/YAYvJ+NfdMMCgYEArpEh
4LoSsKPdaZMqZkafXeyvzdA8Obcz5EggVyeAcK5un472aBmv+Dw0ROQKMoWvVya6
EnnqMI5oGptPM4ocNQDukEUf8xtvsiAa3Hmk1X9LW9y03RQZYbKFG+IztPpdNHl9
fD3WQFdK2K1NCSfRYUjzCdGCwMzzrjPrqx+9NpsCgYB3vpgo98NIjB41U1Q6dNNg
DXj2N9nNc4qvP1eNpjbMPG768Q0UXINdj+GWUiinojtQnnnhPFp8Fc6SeErpLTXE
zfWrD0YwO9mqosbj5VbkslSzRSofMYbszMnSZ0R3TqZRSNpKnHCMCM/+53P24Wi2
8m/gxG9DSnu/6QYvqowSiwKBgBK2Sexd5bz7g7NabBQUg+a8hUfJh3skUTKqLJVL
DbCGciM2XuFfx4YTZgLwcsthmx77brymRt03lp8rgLzklAt2cxwR3M/hZAKzAE4b
1/husbRCHz0Hd4UKbsxDXgmLQMxsLXBQ7JNvB/3b7cMKep40BKFLzPk/vuswc5Wf
TFf7AoGBAJWMsF0Fxu1APVfrgeEE+1vWdyUDAINlNLuD2wWSu+8J1Kzg0p4LmyR2
UOuQUESja64DUJcIEMzgB3xngApvNL/3PnQlM6+ZL3fS+MXGOrpofNhxBLJbLuoN
WA2V2idzoQRfDRW1xzJu11xJKMUAmnyU17iUePgZ2m0vO+EY4Tgc
-----END RSA PRIVATE KEY-----`

	deprecatedUserAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAk08FgfnXRPpH7muT60xJrvsYXkqJ3LIPKyEBR9wWWHmN8bR8
c3SPPCsmI6ykAsa4IavnwS5vY64/4kcL2IFz9EqMbdNqSjT1dly3a7rwi/lT9E85
fe6mzaBz7460SANmFdB/e/9e6NVQWZvSsZ2T0QQFmDq+peQg4CbdbuQ95cb5vnDI
pWApiRS2zKUo9SLgrF1xgDSmSMHINn4SswS4Zaory/VmsElWPCxBs30k35qRfq5l
NZFjCgfC875CUHylnv+uddycdnP4Dw1aN31D7zyLkTsFh4DG62D0ui+SO8Vzecd5
erpgFm5Q0E1fKYFSotlvInXjHnaU2cer6UhkEwIDAQABAoIBAArCg+F5kVrNeUGW
BAj02pD4cFA625UOQINi9sf78Hnn7xFPoKOCSRAZCsEiVByLzVlQSC5ZKPO7/5iU
ne3jjseyRk2jWqku8xsBLLimv/lJbfNzcfyb2P0+EhnWb56u+N7xCs7Q2WriYesZ
sasdmnVy+MGk0NYnMquMyzHVZBwLb0JZ28Rfg1krs3Ot8kWScGKBjlSEXftf11hz
pNcoidyNx5UrPplGNFn+uSZ2YqKp/D3b91pmCTaGWETC3NX3DPqyVB6An5Rto+yg
wIY/KDEQVdyxYbxKzIji6Y2QNgogxjY8Bf8kJt8m3xU6+rcGY766j/6yxnv3pKr0
l4y2UXECgYEAyH80IBLFPRoHSW3As9elo2hhUCc+b5do0G5nD3F4dPMUj/oX7mrr
S3CVczX2duRd/L/Gso/6i3I0cWbA/DtPmqE6iDoJogGF/Ht1HwxLZFcPgsYEXiSp
7NgdxS/7bkAoCKwBKh0lZdrpJGJf334v8zhfcdR43s4/QirgiJKx87sCgYEAvBZ6
9EkOxa3VS5sIt+G3UaTIlghwmTaf5RogP7JriKS2b90NIZvMcO2LMa6yhsd9dIG3
BXcK22nbnmSo6CF7ZDTWDu0eN71vKsiOK0ko3Zqbk+OWJJiOZe//FaGIY9FS2beR
kXStM8/vlSJcGDBP/p01+uJZXSeDLK6Dv6N/D4kCgYByE/ZrnWJ+bpXg0MLJURTc
0iI0ge/DfKnVlkurfMul9z0m4ozFSi6Q4QEX6YdPhIZ5rgB3TvamaxetwmJh4blc
aQotwqACfs1mqDQus0ceU27u4I5RppjMuvbNYIy14Wkl7gBHnwfNWW44FoUoW9sa
j2O3F8aiN0XE9zKEYrs/ywKBgQC7AMLYdHa6df3WgNrnMAS6qNJB0TxaKKRK/XHI
wtUFc3Zru+TdYHCgapz1FZMsS9Vg68MTLOtfgV04my4QNZHf7GRTTM+5bZ/Ecshf
Iwr9YUWDgUh7NC6IDViZohPf4nO0QT36132JQRkcNqBH8GjoZlgQC9H7u1hBKXWW
KLEguQKBgDJAG9NfRiIAtUKxcNhg09UUP0jNWdGF2k9BI75HWEeUsgE++TZcC/Po
DN+17hUNEB2VOWVydpTkRCl5ws+ankX5jvvVRAxqbfB+Kf33J5o/kINzzo+NFccA
bHzHsuuOvQwzlLS06P/VkVlF8bAsA/ajgNCDz1vC8lBrcmEugrYC
-----END RSA PRIVATE KEY-----`
)
