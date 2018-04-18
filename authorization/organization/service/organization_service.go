package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application"
	organization "github.com/fabric8-services/fabric8-auth/authorization/organization"
	organizationModel "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	uuid "github.com/satori/go.uuid"
)

type OrganizationService interface {
	CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]organization.IdentityOrganization, error)
}

type OrganizationServiceImpl struct {
	modelService organizationModel.OrganizationModelService
	db           application.DB
}

func NewOrganizationService(modelService organizationModel.OrganizationModelService, db application.DB) OrganizationService {
	return &OrganizationServiceImpl{modelService: modelService, db: db}
}

func (s *OrganizationServiceImpl) CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error) {

	var organizationId *uuid.UUID
	var err error

	err = application.Transactional(s.db, func(appl application.Application) error {
		organizationId, err = s.modelService.CreateOrganization(ctx, appl, identityID, organizationName)
		return err
	})

	return organizationId, err
}

func (s *OrganizationServiceImpl) ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]organization.IdentityOrganization, error) {
	var orgs []organization.IdentityOrganization
	var err error
	err = application.Transactional(s.db, func(appl application.Application) error {
		orgs, err = s.modelService.ListOrganizations(ctx, appl, identityID)
		return err
	})

	return orgs, err
}
