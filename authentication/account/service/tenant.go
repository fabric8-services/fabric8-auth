package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/authentication/account/tenant"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	goauuid "github.com/goadesign/goa/uuid"
	"github.com/satori/go.uuid"
)

// TenantService represents the Tenant service
type TenantService interface {
	Init(ctx context.Context) error
	Delete(ctx context.Context, identityID uuid.UUID) error
}

type tenantConfig interface {
	GetTenantServiceURL() string
}

type tenantServiceImpl struct {
	config tenantConfig
	doer   rest.HttpDoer
}

// NewTenantService creates a new tenant service
func NewTenantService(config tenantConfig) TenantService {
	return &tenantServiceImpl{config: config, doer: rest.DefaultHttpDoer()}
}

// Init creates a new tenant in OSO
func (t *tenantServiceImpl) Init(ctx context.Context) error {
	c, err := t.createClientWithContextSigner(ctx)
	if err != nil {
		return err
	}

	// Ignore response for now
	response, err := c.SetupTenant(goasupport.ForwardContextRequestID(ctx), tenant.SetupTenantPath())
	if err == nil {
		defer rest.CloseResponse(response)
	}

	return err
}

// Delete deletes tenants for the identity
func (t *tenantServiceImpl) Delete(ctx context.Context, identityID uuid.UUID) error {
	c, err := t.createClientWithServiceAccountSigner(ctx)
	if err != nil {
		return err
	}

	tenantID, err := goauuid.FromString(identityID.String())
	if err != nil {
		return err
	}

	response, err := c.DeleteTenants(goasupport.ForwardContextRequestID(ctx), tenant.DeleteTenantsPath(tenantID))
	if err != nil {
		return err
	}
	defer rest.CloseResponse(response)
	respBody := rest.ReadBody(response.Body)

	if response.StatusCode != http.StatusNoContent {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID.String(),
			"response_status": response.Status,
			"response_body":   respBody,
		}, "unable to delete tenants")
		return errors.New("unable to delete tenant")
	}

	return nil
}

// createClientWithContextSigner creates with a signer based on current context
func (t *tenantServiceImpl) createClientWithContextSigner(ctx context.Context) (*tenant.Client, error) {
	c, err := t.createClient(ctx)
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}

// createClientWithSASigner creates a client with a JWT signer which uses the Auth Service Account token
func (t *tenantServiceImpl) createClientWithServiceAccountSigner(ctx context.Context) (*tenant.Client, error) {
	c, err := t.createClient(ctx)
	if err != nil {
		return nil, err
	}
	signer, err := manager.AuthServiceAccountSigner(ctx)
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(signer)
	return c, nil
}

func (t *tenantServiceImpl) createClient(ctx context.Context) (*tenant.Client, error) {
	u, err := url.Parse(t.config.GetTenantServiceURL())
	if err != nil {
		return nil, err
	}

	c := tenant.New(t.doer)
	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
