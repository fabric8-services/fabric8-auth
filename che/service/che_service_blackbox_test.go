package service_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	cheservice "github.com/fabric8-services/fabric8-auth/che/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	mockcheservice "github.com/fabric8-services/fabric8-auth/test/generated/che/service"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

func TestChe(t *testing.T) {
	suite.Run(t, &TestCheSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type TestCheSuite struct {
	gormtestsupport.DBTestSuite
}

func (s *TestCheSuite) TestDeleteUser() {
	defer gock.OffAll()
	gock.Observe(gock.DumpRequest)

	svcCtx := factory.NewServiceContext(s.Application, s.Application, s.Configuration, nil)
	config := mockcheservice.NewConfigurationMock(s.T())
	config.GetCheServiceURLFunc = func() string {
		return "http://che.test"
	}
	config.GetUserAccountPrivateKeyFunc = func() ([]byte, string) {
		return s.Configuration.GetUserAccountPrivateKey() // reuse value from default config
	}
	config.GetDeprecatedUserAccountPrivateKeyFunc = func() ([]byte, string) {
		return s.Configuration.GetDeprecatedUserAccountPrivateKey() // reuse value from default config
	}
	config.GetServiceAccountPrivateKeyFunc = func() ([]byte, string) {
		return s.Configuration.GetServiceAccountPrivateKey() // reuse value from default config
	}
	config.GetDeprecatedServiceAccountPrivateKeyFunc = func() ([]byte, string) {
		return s.Configuration.GetDeprecatedServiceAccountPrivateKey() // reuse value from default config
	}
	config.GetDevModePublicKeyFunc = func() (bool, []byte, string) {
		return s.Configuration.GetDevModePublicKey() // reuse value from default config
	}
	config.GetAuthServiceURLFunc = func() string {
		return s.Configuration.GetAuthServiceURL() // reuse value from default config
	}
	config.IsPostgresDeveloperModeEnabledFunc = func() bool {
		return s.Configuration.IsPostgresDeveloperModeEnabled() // reuse value from default config
	}
	config.GetAccessTokenExpiresInFunc = func() int64 {
		return s.Configuration.GetAccessTokenExpiresIn() // reuse value from default config
	}
	config.GetTransientTokenExpiresInFunc = func() int64 {
		return s.Configuration.GetTransientTokenExpiresIn() // reuse value from default config
	}
	svc := cheservice.NewCheService(svcCtx, config)
	s.Run("ok", func() {
		// given
		identity := s.Graph.CreateIdentity().Identity()
		tokenManager, err := manager.DefaultManager(config)
		require.NoError(s.T(), err)
		tokenMatcher := gock.NewBasicMatcher()
		tokenMatcher.Add(func(req *http.Request, ereq *gock.Request) (bool, error) {
			h := req.Header.Get("Authorization")
			if strings.HasPrefix(h, "Bearer ") {
				token := h[len("Bearer "):]
				// parse the token and check the 'sub' claim
				tk, err := tokenManager.Parse(context.Background(), token)
				if err != nil {
					return false, err
				}
				if claims, ok := tk.Claims.(jwt.MapClaims); ok {
					return claims["sub"] == identity.ID.String(), nil
				}
			}
			return false, nil
		})
		gock.New("http://che.test").
			Delete(fmt.Sprintf("api/user/%s", identity.ID)).
			SetMatcher(tokenMatcher).
			Reply(200)
		// when
		err = svc.DeleteUser(s.Ctx, *identity)
		// then
		require.NoError(s.T(), err)
	})

}
