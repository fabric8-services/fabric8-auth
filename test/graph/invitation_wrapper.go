package graph

import (
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

// invitationWrapper represents an invitation domain object
type invitationWrapper struct {
	baseWrapper
	invitation *invitation.Invitation
}

func newInvitationWrapper(g *TestGraph, params []interface{}) interface{} {
	w := invitationWrapper{baseWrapper: baseWrapper{g}}

	w.invitation = &invitation.Invitation{Member: true}

	var identityID *uuid.UUID
	var resourceID *string
	var inviteTo *uuid.UUID

	for i := range params {
		switch t := params[i].(type) {
		case resource.Resource:
			resourceID = &t.ResourceID
		case *userWrapper:
			identityID = &t.Identity().ID
		case userWrapper:
			identityID = &t.Identity().ID
		case *organizationWrapper:
			orgID := t.OrganizationID()
			inviteTo = &orgID
		case organizationWrapper:
			orgID := t.OrganizationID()
			inviteTo = &orgID
		case *teamWrapper:
			teamID := t.TeamID()
			inviteTo = &teamID
		case teamWrapper:
			teamID := t.TeamID()
			inviteTo = &teamID
		}
	}

	// The invitation is either for an identity (e.g. org, team), or for a resource (e.g. space), but not both
	if identityID != nil {
		w.invitation.IdentityID = *identityID
	} else if resourceID == nil {
		w.invitation.IdentityID = w.graph.CreateUser().Identity().ID
	} else if resourceID != nil {
		w.invitation.ResourceID = resourceID
	}

	if inviteTo != nil {
		w.invitation.InviteTo = inviteTo
	} else {
		orgID := w.graph.CreateOrganization().OrganizationID()
		w.invitation.InviteTo = &orgID
	}

	err := g.app.InvitationRepository().Create(g.ctx, w.invitation)
	require.NoError(g.t, err)

	return &w
}

func (w *invitationWrapper) Invitation() *invitation.Invitation {
	return w.invitation
}
