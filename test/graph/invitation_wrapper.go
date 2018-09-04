package graph

import (
	"github.com/fabric8-services/fabric8-auth/app"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role/repository"
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

	roles := make([]*repository.Role, 0)

	for i := range params {
		switch t := params[i].(type) {
		case resource.Resource:
			resourceID = &t.ResourceID
		case *spaceWrapper:
			resourceID = &t.Resource().ResourceID
		case spaceWrapper:
			resourceID = &t.Resource().ResourceID
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
		case bool:
			w.invitation.Member = t
		case *roleWrapper:
			roles = append(roles, t.Role())
		case roleWrapper:
			roles = append(roles, t.Role())
		case *repository.Role:
			roles = append(roles, t)
		case repository.Role:
			roles = append(roles, &t)
		case *app.RedirectURL:
			w.invitation.SuccessRedirectURL = *t.OnSuccess
			w.invitation.FailureRedirectURL = *t.OnFailure
		}
	}

	if identityID != nil {
		w.invitation.IdentityID = *identityID
	} else {
		w.invitation.IdentityID = w.graph.CreateUser().Identity().ID
	}

	// The invitation is either for an identity (e.g. org, team), or for a resource (e.g. space), but not both
	if inviteTo != nil {
		w.invitation.InviteTo = inviteTo
	} else if resourceID != nil {
		w.invitation.ResourceID = resourceID
	} else {
		teamID := w.graph.CreateTeam().TeamID()
		w.invitation.InviteTo = &teamID
	}

	err := g.app.InvitationRepository().Create(g.ctx, w.invitation)
	require.NoError(g.t, err)

	for _, role := range roles {
		g.app.InvitationRepository().AddRole(g.ctx, w.invitation.InvitationID, role.RoleID)
	}

	return &w
}

func (w *invitationWrapper) Invitation() *invitation.Invitation {
	return w.invitation
}
