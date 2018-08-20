package test

import (
	"context"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/wit"
	"github.com/goadesign/goa/uuid"
)

// DevWITService is the default dev service implementation for WIT.
type DevWITService struct {
	SpaceID     uuid.UUID
	OwnerID     uuid.UUID
	Name        string
	Description string
}

func (s *DevWITService) UpdateUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, identityID string) error {
	return nil
}

func (s *DevWITService) CreateUser(ctx context.Context, identity *account.Identity, identityID string) error {
	return nil
}

func (s *DevWITService) GetSpace(ctx context.Context, spaceID string) (space *wit.Space, e error) {
	return &wit.Space{ID: s.SpaceID, OwnerID: s.OwnerID, Name: s.Name, Description: s.Description}, nil
}
