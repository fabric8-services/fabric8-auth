package factory

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	teamservice "github.com/fabric8-services/fabric8-auth/authorization/team/service"
)

type ServiceContextProducer func() *service.ServiceContext

type ServiceFactory struct {
	contextProducer ServiceContextProducer
}

func NewServiceFactory(producer ServiceContextProducer) ServiceFactory {
	return ServiceFactory{contextProducer: producer}
}

func (f *ServiceFactory) getContext() *service.ServiceContext {
	return f.contextProducer()
}

func (f *ServiceFactory) OrganizationService() service.OrganizationService {
	return organizationservice.NewOrganizationService(f.getContext())
}

func (f *ServiceFactory) InvitationService() service.InvitationService {
	return invitationservice.NewInvitationService(f.getContext())
}

func (f *ServiceFactory) PermissionService() service.PermissionService {
	return permissionservice.NewPermissionService(f.getContext())
}

func (f *ServiceFactory) RoleManagementService() service.RoleManagementService {
	return roleservice.NewRoleManagementService(f.getContext())
}

func (f *ServiceFactory) TeamService() service.TeamService {
	return teamservice.NewTeamService(f.getContext())
}
