package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/account/tenant"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-common/convert/ptr"
	"github.com/goadesign/goa"
	goauuid "github.com/goadesign/goa/uuid"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

var (
	pts = ptr.String
	ptb = ptr.Bool
)

type UserServiceControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestUserServiceController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &UserServiceControllerTestSuite{})
}

func (s *UserServiceControllerTestSuite) SecuredController(identity repository.Identity) (*goa.Service, *UserServiceController) {
	svc := testsupport.ServiceAsUser("User-Service", identity)
	controller := NewUserServiceController(svc, s.Application)
	return svc, controller
}

func (s *UserServiceControllerTestSuite) UnsecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Userinfo-Service")
	controller := NewUserinfoController(svc, s.Application, testtoken.TokenManager)
	return svc, controller
}

func (s *UserServiceControllerTestSuite) TestShowInternalError() {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestShowUserOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	svc, ctrl := s.SecuredController(identity)
	test.ShowUserServiceInternalServerError(s.T(), svc.Context, svc, ctrl)
}

func Test_convert(t *testing.T) {
	nsTime := time.Now()
	nsInput := []*tenant.NamespaceAttributes{
		{
			CreatedAt:                &nsTime,
			UpdatedAt:                &nsTime,
			Name:                     pts("foons"),
			State:                    pts("created"),
			Version:                  pts("1.0"),
			Type:                     pts("che"),
			ClusterURL:               pts("http://test.org"),
			ClusterConsoleURL:        pts("https://console.example.com/console"),
			ClusterMetricsURL:        pts("https://metrics.example.com"),
			ClusterLoggingURL:        pts("https://console.example.com/console"),
			ClusterAppDomain:         pts("apps.example.com"),
			ClusterCapacityExhausted: ptb(true),
		},
	}

	tenantID := goauuid.NewV4()
	tenantCreated := time.Now()
	tenantSingle := &tenant.TenantSingle{
		Data: &tenant.Tenant{
			ID: &tenantID,
			Attributes: &tenant.TenantAttributes{
				CreatedAt:  &tenantCreated,
				Namespaces: nsInput,
			},
		},
	}

	nsOutput := []*app.NamespaceAttributes{
		{
			CreatedAt:                &nsTime,
			UpdatedAt:                &nsTime,
			Name:                     pts("foons"),
			State:                    pts("created"),
			Version:                  pts("1.0"),
			Type:                     pts("che"),
			ClusterURL:               pts("http://test.org"),
			ClusterConsoleURL:        pts("https://console.example.com/console"),
			ClusterMetricsURL:        pts("https://metrics.example.com"),
			ClusterLoggingURL:        pts("https://console.example.com/console"),
			ClusterAppDomain:         pts("apps.example.com"),
			ClusterCapacityExhausted: ptb(true),
		},
	}
	tenantIDConv, err := uuid.FromString(tenantID.String())
	require.NoError(t, err)
	expected := &app.UserServiceSingle{
		Data: &app.UserService{
			Attributes: &app.UserServiceAttributes{
				CreatedAt:  &tenantCreated,
				Namespaces: nsOutput,
			},
			ID:   &tenantIDConv,
			Type: "userservices",
		},
	}

	actual := convert(tenantSingle)
	require.Equal(t, expected, actual)
}
