package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/authorization"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	resourceservice "github.com/fabric8-services/fabric8-auth/authorization/resource/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
	"github.com/satori/go.uuid"
	"reflect"
)

var OrganizationServiceType reflect.Type

type OrganizationService interface {
	CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

//Services creates instances of service layer objects
type Services interface {
	InvitationService() invitationservice.InvitationService
	OrganizationService() OrganizationService
	PermissionService() permissionservice.PermissionService
	RoleManagementService() roleservice.RoleManagementService
	TeamService() teamservice.TeamService
	ResourceService() resourceservice.ResourceService
}

func init() {
	var svc *OrganizationService
	OrganizationServiceType = reflect.TypeOf(svc)
}
