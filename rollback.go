package ibmcloudsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	walTypeServiceID   = "serviceID"
	walTypeResourceKey = "resourceKey"
)

func (b *ibmCloudSecretBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind == walTypeServiceID {
		serviceID := data.(string)

		adminToken, err := b.getAdminToken(ctx, req.Storage)
		if err != nil {
			b.Logger().Error("error obtaining the token for the configured API key", "error", err)
			return err
		}
		b.Logger().Debug("rolling back serviceID", "serviceID", serviceID)

		iam, resp := b.getAPIHelper(ctx, req.Storage)
		if resp != nil {
			b.Logger().Error("failed to retrieve an API helper", "error", resp.Error())
			return resp.Error()
		}

		err = iam.DeleteServiceID(adminToken, serviceID)

		return err
	} else if kind == walTypeResourceKey {
		resourceKeyGUID := data.(string)

		adminToken, err := b.getAdminToken(ctx, req.Storage)
		if err != nil {
			b.Logger().Error("error obtaining the token for the configured API key", "error", err)
			return err
		}
		b.Logger().Debug("rolling back resource key", "resource key", resourceKeyGUID)

		iam, resp := b.getAPIHelper(ctx, req.Storage)
		if resp != nil {
			b.Logger().Error("failed to retrieve an API helper", "error", resp.Error())
			return resp.Error()
		}

		err = iam.DeleteCOSResourceKey(adminToken, resourceKeyGUID)

		return err
	} else {
		return fmt.Errorf("unknown type to rollback %q", kind)
	}
}
