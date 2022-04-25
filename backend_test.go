package ibmcloudsecrets

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(tb testing.TB) (*ibmCloudSecretBackend, logical.Storage) {
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
	return b, config.StorageView
}
