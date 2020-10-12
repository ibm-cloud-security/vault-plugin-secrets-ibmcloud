package ibmcloudsecrets

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
	"time"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type ibmCloudSecretBackend struct {
	*framework.Backend
	adminTokenLock   sync.RWMutex
	adminToken       string
	adminTokenExpiry time.Time
	iamHelperLock    sync.RWMutex
	iamHelper        iamHelper
}

func backend(c *logical.BackendConfig) *ibmCloudSecretBackend {
	b := &ibmCloudSecretBackend{}
	b.iamHelper = new(ibmCloudHelper)
	b.iamHelper.Init()

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathSecretServiceIDKey(b),
			},
			pathsRole(b),
		),
		Secrets: []*framework.Secret{
			secretServiceIDKey(b),
		},

		Clean:       b.cleanup,
		Invalidate:  b.invalidate,
		WALRollback: b.walRollback,

		WALRollbackMinAge: 5 * time.Minute,
	}
	return b
}

func (b *ibmCloudSecretBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *ibmCloudSecretBackend) reset() {
	b.adminTokenLock.Lock()
	unlockFunc := b.adminTokenLock.Unlock
	defer func() { unlockFunc() }()

	b.adminTokenExpiry = time.Now()
	b.adminToken = ""
}

func (b *ibmCloudSecretBackend) cleanup(_ context.Context) {
	b.iamHelper.Cleanup()
}

func (b *ibmCloudSecretBackend) getAdminToken(ctx context.Context, s logical.Storage) (string, error) {
	b.adminTokenLock.RLock()
	unlockFunc := b.adminTokenLock.RUnlock
	defer func() { unlockFunc() }()
	if b.adminToken != "" && (time.Until(b.adminTokenExpiry).Minutes() > adminTokenRenewBeforeExpirationMinutes) {
		return b.adminToken, nil
	}
	b.adminTokenLock.RUnlock()

	b.adminTokenLock.Lock()
	unlockFunc = b.adminTokenLock.Unlock
	if b.adminToken != "" && (time.Until(b.adminTokenExpiry).Minutes() > adminTokenRenewBeforeExpirationMinutes) {
		return b.adminToken, nil
	}

	config, err := b.config(ctx, s)
	if err != nil {
		b.Logger().Error("failed to load configuration")
		return "", err
	}

	if config == nil || config.APIKey == "" {
		return "", errors.New("no API key was set in the configuration")
	}

	token, err := b.iamHelper.ObtainToken(config.APIKey)
	if err != nil {
		b.Logger().Error("failed to obtain the access token using the configured API key configuration", "error", err)
		return "", err
	}
	adminTokenInfo, resp := b.iamHelper.VerifyToken(ctx, token)
	if resp != nil {
		return "", resp.Error()
	}
	b.adminToken = token
	b.adminTokenExpiry = adminTokenInfo.Expiry
	return b.adminToken, nil
}

const backendHelp = `
The IBM Cloud backend plugin allows authentication for IBM Public Cloud.
`
