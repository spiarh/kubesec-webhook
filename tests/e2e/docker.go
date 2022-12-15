package e2e

import (
	"context"
	"fmt"
	"path"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/google/uuid"
	"github.com/vladimirvivien/gexe"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const defaultRepo = "e2e.kubesec.io/kubesec-webhook"

type contextKey int

const (
	dockerImage contextKey = iota
	dockerImageRepo
	dockerImageTag
)

func buildDockerImage(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	klog.InfoS("Building docker image")

	repo := defaultRepo
	tag := uuid.New().String()
	image := repo + ":" + tag

	dockerClient, err := client.NewClientWithOpts()
	if err != nil {
		return ctx, err
	}

	tar, err := archive.TarWithOptions(path.Join("..", ".."), &archive.TarOptions{
		// Add only the code for the webhook to avoid rebuilding
		// the image for unrelated changes.
		IncludeFiles: []string{
			"Dockerfile",
			"go.mod", "go.sum",
			"cmd", "pkg", "tests/testdata"}})
	if err != nil {
		return ctx, err
	}
	defer tar.Close()

	resp, err := dockerClient.ImageBuild(ctx, tar, types.ImageBuildOptions{
		Dockerfile:     "Dockerfile",
		Tags:           []string{image},
		Remove:         true,
		SuppressOutput: true,
	})
	if err != nil {
		return ctx, err
	}
	defer resp.Body.Close()

	ctx = context.WithValue(ctx, dockerImageRepo, repo)
	ctx = context.WithValue(ctx, dockerImageTag, tag)
	ctx = context.WithValue(ctx, dockerImage, image)

	return ctx, nil
}

func getDockerImageValue(ctx context.Context, key contextKey) (string, error) {
	val := ctx.Value(key)
	if val == nil {
		return "", fmt.Errorf("no value found, buildDockerImage must run before calling this")
	}

	v, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("value from context is not a string")
	}

	return v, nil
}

func kindLoadDockerImage(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Loading docker image into Kind cluster")

		image, err := getDockerImageValue(ctx, dockerImage)
		if err != nil {
			return ctx, err
		}

		cmd := fmt.Sprintf("kind load docker-image %s --name %s", image, clusterName)
		p := gexe.New().RunProc(cmd)
		if p.Err() != nil {
			return ctx, fmt.Errorf("Unable to load docker image to kind cluster: %w", p.Err())
		}

		return ctx, nil
	}
}
