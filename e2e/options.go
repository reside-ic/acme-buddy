package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/go-acme/lego/v4/certificate"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// This testcontainer option sets up an anonymous volume at the given path,
// only if no other volume is configured at this path. This will only work
// reliably if this option is passed after any other option that might set up a
// volume at that path.
func WithDefaultVolumeMount(target tc.ContainerMountTarget) tc.CustomizeRequestOption {
	return func(req *tc.GenericContainerRequest) error {
		for _, m := range req.Mounts {
			if m.Target == target {
				return nil
			}
		}
		req.Mounts = append(req.Mounts, tc.ContainerMount{
			Source: tc.DockerVolumeMountSource{
				VolumeOptions: &mount.VolumeOptions{Labels: tc.GenericLabels()},
			},
			Target: target,
		})

		return nil
	}
}

func WithInitialCertificate(cert *certificate.Resource) tc.CustomizeRequestOption {
	return tc.WithFiles(
		tc.ContainerFile{
			Reader:            bytes.NewReader(cert.Certificate),
			ContainerFilePath: "/tls/certificate.pem",
		},
		tc.ContainerFile{
			Reader:            bytes.NewReader(cert.PrivateKey),
			ContainerFilePath: "/tls/key.pem",
		},
	)
}

func WithBindMountedDockerSocket(ctx context.Context) tc.ContainerCustomizer {
	return tc.WithMounts(tc.ContainerMount{
		Source: tc.DockerBindMountSource{
			HostPath: tc.MustExtractDockerSocket(ctx),
		},
		Target: "/var/run/docker.sock",
	})
}

type SuccessStrategy struct{ *wait.ExitStrategy }

// This is similar to testcontainer's built-in `wait.ForExit()` strategy, in
// that it will wait until the container exits. It will however check the exit
// code and return a permanent error if the container exited with a non-zero
// error.
//
// https://pkg.go.dev/github.com/testcontainers/testcontainers-go@v0.37.0/wait#ForExit
func WaitForSuccess() *SuccessStrategy {
	return &SuccessStrategy{wait.ForExit()}
}

func (ss *SuccessStrategy) WaitUntilReady(ctx context.Context, target wait.StrategyTarget) error {
	err := ss.ExitStrategy.WaitUntilReady(ctx, target)
	if err != nil {
		return err
	}

	state, err := target.State(ctx)
	if err != nil {
		return err
	}
	if state.Status != container.StateExited {
		return errors.New("unexpected status")
	}
	if state.ExitCode != 0 {
		return wait.NewPermanentError(fmt.Errorf("container exited with non-zero code: %d", state.ExitCode))
	}
	return nil
}
