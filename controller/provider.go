package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/provider"
	"github.com/goadesign/goa"
	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// ProviderController implements the provider resource.
type ProviderController struct {
	*goa.Controller
	db                              application.DB
	externalProviderTokenRepository provider.ExternalProviderTokenRepository
}

// NewProviderController creates a provider controller.
func NewProviderController(service *goa.Service, db application.DB, externalProviderTokenRepository provider.ExternalProviderTokenRepository) *ProviderController {
	return &ProviderController{
		Controller: service.NewController("ProviderController"),
		db:         db,
		externalProviderTokenRepository: externalProviderTokenRepository,
	}
}

// Get runs the get action.
func (c *ProviderController) Get(ctx *app.GetProviderContext) error {

	// TODO: Use ID from the context.
	sampleUUID, _ := uuid.FromString("4ed215d0-4f0f-4d4d-8098-3f9600edb0a5")

	token, err := c.externalProviderTokenRepository.Load(ctx, sampleUUID, ctx.Provider)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Unable to get fetch token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to fetch token")))
	}

	res := &app.AuthToken{
		Token: &app.TokenData{
			AccessToken: &token.Token,
		},
	}
	return ctx.OK(res)
}
