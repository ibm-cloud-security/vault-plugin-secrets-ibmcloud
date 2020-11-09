package ibmcloudsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	walTypeServiceID = "serviceID"
)

func (b *ibmCloudSecretBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != walTypeServiceID {
		return fmt.Errorf("unknown type to rollback %q", kind)
	}
	serviceID := data.(string)

	adminToken, err := b.getAdminToken(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("error obtaining the token for the configured API key", "error", err)
		return err
	}
	b.Logger().Debug("rolling back serviceID", "serviceID", serviceID)

	err = b.iamHelper.DeleteServiceID(adminToken, serviceID)

	return err
}
