package controller

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/account/tenant"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	servicemock "github.com/fabric8-services/fabric8-auth/test/generated/application/service"
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
	tenantServiceMock := servicemock.NewTenantServiceMock(s.T())
	tenantServiceMock.ViewFunc = func(ctx context.Context) (*tenant.TenantSingle, error) {
		nsTime := time.Now()
		nsInput := []*tenant.NamespaceAttributes{
			{
				CreatedAt:                &nsTime,
				UpdatedAt:                &nsTime,
				Name:                     pts("foo"),
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

		return tenantSingle, nil
	}
	controller := NewUserServiceController(svc, gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithTenantService(tenantServiceMock)))
	return svc, controller
}

func (s *UserServiceControllerTestSuite) UnsecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Userinfo-Service")
	controller := NewUserinfoController(svc, s.Application, testtoken.TokenManager)
	return svc, controller
}

func (s *UserServiceControllerTestSuite) TestShowOK() {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestShowUserOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	svc, ctrl := s.SecuredController(identity)
	_, userService := test.ShowUserServiceOK(s.T(), svc.Context, svc, ctrl)

	require.Len(s.T(), userService.Data.Attributes.Namespaces, 1)
	require.Equal(s.T(), "foo", *userService.Data.Attributes.Namespaces[0].Name)
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
