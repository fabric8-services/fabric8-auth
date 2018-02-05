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
)

const RESOURCE_TYPE_ORGANIZATION = "identity/organization"
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

	var organizationId uuid.UUID

	err = application.Transactional(c.db, func(appl application.Application) error {

		// Lookup the identity for the current user
		userIdentity, err := appl.Identities().Load(ctx, *currentUser)
		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "Error looking up current user")
		}

		// Lookup the organization resource type
		resourceType, err := appl.ResourceTypeRepository().Lookup(ctx, RESOURCE_TYPE_ORGANIZATION)
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
		ownerRole, err := appl.RoleRepository().Lookup(ctx, ORGANIZATION_OWNER_ROLE, RESOURCE_TYPE_ORGANIZATION)

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
	// OrganizationController_List: start_implement

	// Put your logic here

	// OrganizationController_List: end_implement
	res := &app.OrganizationArray{}
	return ctx.OK(res)
}
