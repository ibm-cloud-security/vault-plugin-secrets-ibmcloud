package ibmcloudsecrets

import (
	"context"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
)

func testBackend(tb testing.TB) (*ibmCloudSecretBackend, logical.Storage) {
	return testBackendWithMock(tb, nil)
}

func testBackendWithMock(tb testing.TB, iamH iamHelper) (*ibmCloudSecretBackend, logical.Storage) {
	tb.Helper()

	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	config := &logical.BackendConfig{
		Logger: log.New(&log.LoggerOptions{Level: log.Trace}),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	b := backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		tb.Fatalf("unable to create backend: %v", err)
	}
	if iamH != nil {
		b.iamHelper.Cleanup()
		b.iamHelper = iamH
	}
	return b, config.StorageView
}
