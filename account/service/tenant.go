package service

import (
	"context"
	"errors"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account/tenant"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	goauuid "github.com/goadesign/goa/uuid"
	"github.com/satori/go.uuid"
	"net/http"
)

type tenantConfig interface {
	GetTenantServiceURL() string
}

// Tenant represents Tenant Service
type Tenant interface {
	Init(ctx context.Context) error
	Delete(ctx context.Context, identityID uuid.UUID) error
}

type tenantService struct {
	config tenantConfig
	doer   rest.HttpDoer
}

// NewTenant creates a new tenant service
func NewTenant(config tenantConfig) Tenant {
	return &tenantService{config: config, doer: rest.DefaultHttpDoer()}
}

// Init creates a new tenant in OSO
func (t *tenantService) Init(ctx context.Context) error {
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
func (t *tenantService) Delete(ctx context.Context, identityID uuid.UUID) error {
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

	if response.StatusCode != http.StatusNoContent {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID.String(),
			"response_status": response.Status,
			"response_body":   rest.ReadBody(response.Body),
		}, "unable to delete tenants")
		return errors.New("unable to delete tenants")
	}

	return nil
}

// createClientWithContextSigner creates with a signer based on current context
func (t *tenantService) createClientWithContextSigner(ctx context.Context) (*tenant.Client, error) {
	c, err := t.createClient(ctx)
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}

// createClientWithSASigner creates a client with a JWT signer which uses the Auth Service Account token
func (t *tenantService) createClientWithServiceAccountSigner(ctx context.Context) (*tenant.Client, error) {
	c, err := t.createClient(ctx)
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}

func (t *tenantService) createClient(ctx context.Context) (*tenant.Client, error) {
	u, err := url.Parse(t.config.GetTenantServiceURL())
	if err != nil {
		return nil, err
	}

	c := tenant.New(t.doer)
	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
