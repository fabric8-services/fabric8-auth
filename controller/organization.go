package controller

import (
	"strings"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/goadesign/goa"
)

const OrganizationOwnerRole = "owner"

// OrganizationController implements the organization resource.
type OrganizationController struct {
	*goa.Controller
	app application.Application
}

// NewOrganizationController creates an organization controller.
func NewOrganizationController(service *goa.Service, app application.Application) *OrganizationController {
	return &OrganizationController{Controller: service.NewController("OrganizationController"), app: app}
}

// Create runs the create action.
func (c *OrganizationController) Create(ctx *app.CreateOrganizationContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	if ctx.Payload.Name == nil || len(strings.TrimSpace(*ctx.Payload.Name)) == 0 {
		log.Error(ctx, map[string]interface{}{}, "organization name cannot be empty")
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("organization name cannot be empty"))
	}

	organizationId, err := c.app.OrganizationService().CreateOrganization(ctx, *currentUser, *ctx.Payload.Name)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"org_name": *ctx.Payload.Name,
		}, "failed to create organization")

		return jsonapi.JSONErrorResponse(ctx, err)
	}

	log.Debug(ctx, map[string]interface{}{
		"organization_id": organizationId.String(),
	}, "organization created")

	orgId := organizationId.String()

	return ctx.Created(&app.CreateOrganizationResponse{&orgId})
}

// List runs the list action.
func (c *OrganizationController) List(ctx *app.ListOrganizationContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if currentUser == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("error finding the current user"))
	}

	orgs, err := c.app.OrganizationService().ListOrganizations(ctx, *currentUser)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to list organizations")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	return ctx.OK(&app.OrganizationArray{convertToAppOrganization(orgs)})
}

func convertToAppOrganization(orgs []authorization.IdentityAssociation) []*app.OrganizationData {
	results := []*app.OrganizationData{}

	for _, org := range orgs {
		orgData := &app.OrganizationData{
			ID:     org.IdentityID.String(),
			Name:   org.ResourceName,
			Member: org.Member,
			Roles:  org.Roles,
		}

		results = append(results, orgData)
	}

	return results
}
