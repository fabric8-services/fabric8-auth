package controller

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"strings"
)

const ORGANIZATION_OWNER_ROLE = "owner"

// OrganizationController implements the organization resource.
type OrganizationController struct {
	*goa.Controller
	db           application.DB
	TokenManager token.Manager
}

// NewOrganizationController creates a organization controller.
func NewOrganizationController(service *goa.Service, db application.DB) *OrganizationController {
	return &OrganizationController{Controller: service.NewController("OrganizationController"), db: db}
}

// Create runs the create action.
func (c *OrganizationController) Create(ctx *app.CreateOrganizationContext) error {
	currentUser, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}

	if len(strings.TrimSpace(*ctx.Payload.Name)) == 0 {
		return jsonapi.JSONErrorResponse(ctx, goa.ErrBadRequest("Organization name cannot be empty"))
	}

	var organizationId uuid.UUID

	err = application.Transactional(c.db, func(appl application.Application) error {

		// Lookup the identity for the current user
		userIdentity, err := appl.Identities().Load(ctx, *currentUser)
		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "Error looking up current user")
		}

		// Lookup the organization resource type
		resourceType, err := appl.ResourceTypeRepository().Lookup(ctx, account.IDENTITY_RESOURCE_TYPE_ORGANIZATION)
		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "Error looking up resource type 'identity/organization'")
		}

		// Create the organization resource
		res := &resource.Resource{
			Name:           *ctx.Payload.Name,
			ResourceType:   *resourceType,
			ResourceTypeID: resourceType.ResourceTypeID,
		}

		err = appl.ResourceRepository().Create(ctx, res)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}

		// Create the organization identity
		orgIdentity := &account.Identity{
			IdentityResourceID: &res.ResourceID,
		}

		err = appl.Identities().Create(ctx, orgIdentity)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}

		organizationId = orgIdentity.ID

		// Lookup the identity/organization owner role
		ownerRole, err := appl.RoleRepository().Lookup(ctx, ORGANIZATION_OWNER_ROLE, account.IDENTITY_RESOURCE_TYPE_ORGANIZATION)

		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "Error looking up owner role for 'identity/organization' resource type")
		}

		// Assign the owner role for the new organization to the current user
		identityRole := &role.IdentityRole{
			IdentityID: userIdentity.ID,
			ResourceID: res.ResourceID,
			RoleID:     ownerRole.RoleID,
		}

		err = appl.IdentityRoleRepository().Create(ctx, identityRole)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
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
		return jsonapi.JSONErrorResponse(ctx, goa.ErrUnauthorized(err.Error()))
	}

	var orgs []account.IdentityOrganization

	err = application.Transactional(c.db, func(appl application.Application) error {

		orgs, err = appl.Identities().ListOrganizations(ctx, *currentUser)

		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, goa.ErrInternal(err.Error()))
		}

		return err
	})

	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

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

	return ctx.OK(&app.OrganizationArray{results})
}
