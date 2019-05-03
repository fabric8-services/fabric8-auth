package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authentication/account/tenant"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

// UserServiceController implements the UserService resource.
type UserServiceController struct {
	*goa.Controller
	app application.Application
}

// NewUserServiceController creates a UserService controller.
func NewUserServiceController(service *goa.Service) *UserServiceController {
	return &UserServiceController{Controller: service.NewController("UserServiceController")}
}

// Show runs the show action.
func (c *UserServiceController) Show(ctx *app.ShowUserServiceContext) error {
	t, err := c.app.TenantService().View(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.OK(convert(t))
}

func convert(t *tenant.TenantSingle) *app.UserServiceSingle {
	var ns []*app.NamespaceAttributes
	for _, tn := range t.Data.Attributes.Namespaces {
		ns = append(ns, &app.NamespaceAttributes{
			CreatedAt:                tn.CreatedAt,
			UpdatedAt:                tn.UpdatedAt,
			Name:                     tn.Name,
			State:                    tn.State,
			Version:                  tn.Version,
			Type:                     tn.Type,
			ClusterURL:               tn.ClusterURL,
			ClusterConsoleURL:        tn.ClusterConsoleURL,
			ClusterMetricsURL:        tn.ClusterMetricsURL,
			ClusterLoggingURL:        tn.ClusterLoggingURL,
			ClusterAppDomain:         tn.ClusterAppDomain,
			ClusterCapacityExhausted: tn.ClusterCapacityExhausted,
		})
	}
	id := uuid.UUID(*t.Data.ID)
	u := app.UserServiceSingle{
		Data: &app.UserService{
			Attributes: &app.UserServiceAttributes{
				CreatedAt:  t.Data.Attributes.CreatedAt,
				Namespaces: ns,
			},
			ID:   &id,
			Type: "userservices",
		},
	}
	return &u
}
