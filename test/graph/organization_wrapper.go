package graph

import (
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// organizationWrapper represents an organization resource domain object
type organizationWrapper struct {
	baseWrapper
	identity *account.Identity
	resource *resource.Resource
	creator  *account.Identity
}

func loadOrganizationWrapper(g *TestGraph, organizationID uuid.UUID) organizationWrapper {
	w := organizationWrapper{baseWrapper: baseWrapper{g}}

	var native account.Identity
	err := w.graph.db.Table("identities").Preload("IdentityResource").Where("ID = ?", organizationID).Find(&native).Error
	require.NoError(w.graph.t, err)

	w.identity = &native

	return w
}

func newOrganizationWrapper(g *TestGraph, params []interface{}) organizationWrapper {
	w := organizationWrapper{baseWrapper: baseWrapper{g}}

	var organizationName *string

	for i := range params {
		switch t := params[i].(type) {
		case string:
			organizationName = &t
		case *userWrapper:
			w.creator = t.Identity()
		case userWrapper:
			w.creator = t.Identity()
		}
	}

	if w.creator == nil {
		w.creator = w.graph.CreateUser().Identity()
	}

	if organizationName == nil {
		nm := "Organization-" + uuid.NewV4().String()
		organizationName = &nm
	}

	organizationIdentityID, err := g.app.OrganizationService().CreateOrganization(g.ctx, w.creator.ID, *organizationName)
	require.NoError(g.t, err)

	w.identity = g.LoadIdentity(organizationIdentityID).Identity()
	organizationResource := g.LoadResource(w.identity.IdentityResourceID.String)
	w.resource = organizationResource.Resource()

	return w
}

func (w *organizationWrapper) OrganizationID() uuid.UUID {
	return w.identity.ID
}

func (w *organizationWrapper) OrganizationName() string {
	return w.identity.IdentityResource.Name
}

func (w *organizationWrapper) Identity() *account.Identity {
	return w.identity
}

func (w *organizationWrapper) Resource() *resource.Resource {
	return w.resource
}

func (w *organizationWrapper) ResourceID() string {
	return w.resource.ResourceID
}

// AddAdmin assigns the admin role to a user for the org
func (w *organizationWrapper) AddAdmin(wrapper interface{}) *organizationWrapper {
	addRole(w.baseWrapper, w.resource, authorization.IdentityResourceTypeOrganization, w.identityIDFromWrapper(wrapper), authorization.OrganizationAdminRole)
	return w
}
