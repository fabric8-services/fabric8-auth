package authorization

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/common"
	"github.com/fabric8-services/fabric8-auth/authorization/models"
	uuid "github.com/satori/go.uuid"
)

type OrganizationService interface {
	CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]common.IdentityOrganization, error)
}

type OrganizationServiceImpl struct {
	modelService models.OrganizationModelService
	db           application.DB
}

func NewOrganizationService(modelService models.OrganizationModelService, db application.DB) OrganizationService {
	return &OrganizationServiceImpl{modelService: modelService, db: db}
}

func (s *OrganizationServiceImpl) CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error) {

	var organizationId *uuid.UUID
	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		organizationId, err = s.modelService.CreateOrganization(ctx, identityID, organizationName)
		return err
	})

	return organizationId, err
}

func (s *OrganizationServiceImpl) ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]common.IdentityOrganization, error) {
	var orgs []common.IdentityOrganization
	var err error
	err = application.Transactional(s.db, func(appl application.Application) error {
		orgs, err = s.modelService.ListOrganizations(ctx, identityID)
		return err
	})

	return orgs, err
}
