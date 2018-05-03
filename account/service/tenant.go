package service

import (
	"context"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account/tenant"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/rest"
)

type tenantConfig interface {
	GetTenantServiceURL() string
}

// Tenant represents Tenant Service
type Tenant interface {
	Init(ctx context.Context) error
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

// createClientWithContextSigner creates with a signer based on current context
func (t *tenantService) createClientWithContextSigner(ctx context.Context) (*tenant.Client, error) {
	c, err := t.createClient(ctx)
	if err != nil {
		return nil, err
	}
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}

// createClientWithSASigner creates with a signer based on Auth Service Account
func (t *tenantService) createClientWithSASigner(ctx context.Context) (*tenant.Client, error) {
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
