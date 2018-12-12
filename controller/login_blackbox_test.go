package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	provider "github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testservice "github.com/fabric8-services/fabric8-auth/test/generated/application/service"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type LoginControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestLoginController(t *testing.T) {
	suite.Run(t, &LoginControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *LoginControllerTestSuite) UnSecuredController(app application.Application) (*goa.Service, *LoginController) {
	svc := testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity)
	return svc, NewLoginController(svc, app)
}

func (s *LoginControllerTestSuite) TestLoginOK() {
	// given
	svc, ctrl := s.UnSecuredController(s.Application)
	redirect := "https://openshift.io"
	// when/then
	test.LoginLoginTemporaryRedirect(s.T(), svc.Context, svc, ctrl, nil, &redirect, nil)
}

func (s *LoginControllerTestSuite) TestOfflineAccessOK() {
	// given
	svc, ctrl := s.UnSecuredController(s.Application)
	offline := "offline_access"
	redirect := "https://openshift.io"

	s.T().Run("with offline scope", func(t *testing.T) {
		// when
		resp := test.LoginLoginTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &redirect, &offline)
		// then
		assert.Contains(t, resp.Header().Get("Location"), "scope=offline_access")
	})

	s.T().Run("without explicit scope", func(t *testing.T) {
		// when
		resp := test.LoginLoginTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &redirect, nil)
		// then
		assert.NotContains(t, resp.Header().Get("Location"), "scope=offline_access")
	})
}

func (s *LoginControllerTestSuite) TestCallbackRedirect() {

	// given
	authProviderServiceMock := testservice.NewAuthenticationProviderServiceMock(s.T())
	app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithAuthenticationProviderService(authProviderServiceMock))
	svc, ctrl := s.UnSecuredController(app)
	identityID := uuid.NewV4()
	responseMode := "fragment"
	referrer := fmt.Sprintf("http://api.foo.com?identity_id=%s&for=github", identityID.String())
	state := provider.OauthStateReference{
		State:        uuid.NewV4().String(),
		Referrer:     referrer,
		ResponseMode: &responseMode,
	}
	req := &http.Request{Host: "api.service.domain.org"}
	rw := httptest.NewRecorder()
	prms := url.Values{
		"state": {uuid.NewV4().String()},
		"code:": {uuid.NewV4().String()},
	}
	ctx := goa.NewContext(testtoken.ContextWithTokenManager(), rw, req, prms)

	s.T().Run("without error", func(t *testing.T) {
		// given
		expectedRedirect := "redirectTo"
		authProviderServiceMock.LoginCallbackFunc = func(ctx context.Context, state string, code string, redirectURL string) (*string, error) {
			return &expectedRedirect, nil
		}
		// when
		resp := test.CallbackLoginTemporaryRedirect(t, ctx, svc, ctrl, nil, &state.State)
		// then
		assert.Equal(t, resp.Header().Get("Location"), expectedRedirect)
		t.Logf("'Location' response header: %v", resp.Header().Get("Location"))
	})

	s.T().Run("with error", func(t *testing.T) {
		// given
		authProviderServiceMock.LoginCallbackFunc = func(ctx context.Context, state string, code string, redirectURL string) (*string, error) {
			return nil, errs.New("error")
		}
		// when/then
		test.CallbackLoginInternalServerError(t, ctx, svc, ctrl, nil, &state.State)
	})
}
