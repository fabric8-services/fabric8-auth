package service

import (
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
)

//Services creates instances of service layer objects
type Services interface {
	InvitationService() invitationservice.InvitationService
	OrganizationService() organizationservice.OrganizationService
	PermissionService() permissionservice.PermissionService
	RoleManagementService() roleservice.RoleManagementService
	TeamService() teamservice.TeamService
}
