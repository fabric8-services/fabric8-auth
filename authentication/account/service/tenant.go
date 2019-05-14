package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authentication/account/tenant"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	autherrs "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	uuid "github.com/satori/go.uuid"

	goauuid "github.com/goadesign/goa/uuid"
)

type tenantConfig interface {
	GetTenantServiceURL() string
}

type tenantServiceImpl struct {
	config tenantConfig
	doer   rest.HttpDoer
}

var _ service.TenantService = &tenantServiceImpl{}

// NewTenantService creates a new tenant service
func NewTenantService(config tenantConfig) service.TenantService {
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

// View fetches the current tenant state.
func (t *tenantServiceImpl) View(ctx context.Context) (*tenant.TenantSingle, error) {
	c, err := t.createClientWithContextSigner(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.ShowTenant(goasupport.ForwardContextRequestID(ctx), tenant.ShowTenantPath())
	if err != nil {
		return nil, err
	}
	defer rest.CloseResponse(res)
	switch res.StatusCode {
	case http.StatusOK:
		tenant, err := c.DecodeTenantSingle(res)
		if err != nil {
			return nil, autherrs.NewInternalError(err)
		}
		return tenant, nil
	case http.StatusNotFound:
		jsonErr, err := c.DecodeJSONAPIErrors(res)
		if err == nil {
			if len(jsonErr.Errors) > 0 {
				log.Error(ctx, map[string]interface{}{
					"error_msg": jsonErr.Errors[0].Detail,
				}, "failed to retrieve tenant")
				return nil, autherrs.NewNotFoundError("tenants", *jsonErr.Errors[0].ID)
			}
		} else {
			log.Error(ctx, map[string]interface{}{"error_msg": err}, "failed to parse JSON-API error response")
		}

	}
	return nil, autherrs.NewInternalError(fmt.Errorf("Unknown response: '%v' (%d)", res.Status, res.StatusCode))
}

// Delete deletes tenants for the identity
func (t *tenantServiceImpl) Delete(ctx context.Context, identityID uuid.UUID) error {
	log.Info(ctx, map[string]interface{}{"identity_id": identityID.String()}, "deleting user on Tenant service")
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

	switch response.StatusCode {
	case http.StatusNoContent:
		// OK
		return nil
	case http.StatusNotFound:
		// May happen if the user has been already deleted from Tenant
		// Log the error but return OK
		log.Warn(ctx, map[string]interface{}{
			"identity_id":     identityID.String(),
			"response_status": response.Status,
			"response_body":   respBody,
		}, "unable to delete tenant which is OK if tenant already deleted")
		return nil
	}

	log.Error(ctx, map[string]interface{}{
		"identity_id":     identityID.String(),
		"response_status": response.Status,
		"response_body":   respBody,
	}, "unable to delete tenants")
	return errors.New("unable to delete tenant")
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
