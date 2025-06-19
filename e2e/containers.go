package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"os"
	"strings"

	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startChallTestSrv(ctx context.Context, nw *tc.DockerNetwork, opts ...tc.ContainerCustomizer) (tc.Container, error) {
	opts = append(
		[]tc.ContainerCustomizer{
			tc.WithLogConsumers(&tc.StdoutLogConsumer{}),
			tc.WithDockerfile(tc.FromDockerfile{
				Context:        "./challtestsrv-hdb",
				BuildLogWriter: os.Stdout,
			}),
			tc.WithWaitStrategy(wait.ForExposedPort()),
			network.WithNetwork([]string{"challtestsrv"}, nw)},
		opts...)
	return tc.Run(ctx, "", opts...)
}

func startPebble(ctx context.Context, nw *tc.DockerNetwork, opts ...tc.ContainerCustomizer) (tc.Container, error) {
	opts = append(
		[]tc.ContainerCustomizer{
			tc.WithLogConsumers(&tc.StdoutLogConsumer{}),
			network.WithNetwork([]string{"pebble"}, nw),
			tc.WithCmd("-dnsserver", "challtestsrv:8053"),
			tc.WithExposedPorts("14000/tcp", "15000/tcp"),
			tc.WithWaitStrategy(wait.ForHTTP("/dir").WithTLS(true, &tls.Config{InsecureSkipVerify: true})),
			tc.WithEnv(map[string]string{"PEBBLE_VA_NOSLEEP": "1"}),
		},
		opts...)

	return tc.Run(ctx, "ghcr.io/letsencrypt/pebble:latest", opts...)
}

func WithNginxConfig(cfg string) tc.CustomizeRequestOption {
	return tc.WithFiles(tc.ContainerFile{
		Reader:            strings.NewReader(cfg),
		ContainerFilePath: "/etc/nginx/nginx.conf",
		FileMode:          0644,
	})
}

func startNginx(ctx context.Context, opts ...tc.ContainerCustomizer) (tc.Container, error) {
	opts = append(
		[]tc.ContainerCustomizer{
			tc.WithLogConsumers(&tc.StdoutLogConsumer{}),
		},
		opts...)
	return tc.Run(ctx, "nginx:latest", opts...)
}

func copyFileFromContainer(ctx context.Context, c tc.Container, path string) ([]byte, error) {
	f, err := c.CopyFileFromContainer(ctx, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}
