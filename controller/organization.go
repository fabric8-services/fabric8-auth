package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"strings"
)

const OrganizationOwnerRole = "owner"

// OrganizationController implements the organization resource.
type OrganizationController struct {
	*goa.Controller
	db           application.DB
	TokenManager token.Manager
}

// NewOrganizationController creates an organization controller.
func NewOrganizationController(service *goa.Service, db application.DB) *OrganizationController {
	return &OrganizationController{Controller: service.NewController("OrganizationController"), db: db}
}

// Create runs the create action.
func (c *OrganizationController) Create(ctx *app.CreateOrganizationContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	if ctx.Payload.Name == nil || len(strings.TrimSpace(*ctx.Payload.Name)) == 0 {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("Organization name cannot be empty"))
	}

	var organizationId *uuid.UUID

	err = application.Transactional(c.db, func(appl application.Application) error {

		organizationId, err = appl.OrganizationService().CreateOrganization(ctx, *currentUser, *ctx.Payload.Name)

		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

		return err
	})

	if err != nil {
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

	var orgs []authorization.IdentityOrganization

	err = application.Transactional(c.db, func(appl application.Application) error {

		orgs, err = appl.OrganizationService().ListOrganizations(ctx, *currentUser)

		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
		}

		return err
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	return ctx.OK(&app.OrganizationArray{convertToAppOrganization(orgs)})
}

func convertToAppOrganization(orgs []authorization.IdentityOrganization) []*app.OrganizationData {
	results := []*app.OrganizationData{}

	for _, org := range orgs {
		orgData := &app.OrganizationData{
			ID:     org.OrganizationID.String(),
			Name:   org.Name,
			Member: org.Member,
			Roles:  org.Roles,
		}

		results = append(results, orgData)
	}

	return results
}
