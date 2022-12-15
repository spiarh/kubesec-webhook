package e2e

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testenv     env.Environment
	clusterName string
)

const (
	webhookNS = "kubesec"
	testNS    = "test"

	helmInstallName = "e2e"
	helmChartName   = "kubesec-webhook"
)

func TestMain(m *testing.M) {
	flag.StringVar(&clusterName, "cluster-name", "kubesec-webhook", "Name of the Kind cluster to use")
	flag.Parse()

	testenv = env.New()

	testenv.Setup(
		setUpEnv(clusterName),
	)

	testenv.Finish(
		tearDownEnv(clusterName),
	)

	testenv.Run(m)
}

func setUpEnv(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Setting up e2e test environment")

		var err error

		for _, fn := range []env.Func{
			createKindCluster(clusterName),
			buildDockerImage,
			kindLoadDockerImage(clusterName),
			createNamespace(webhookNS),
			createNamespace(testNS),
			enableValidationOnNS(testNS),
		} {
			ctx, err = fn(ctx, cfg)
			if err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	}
}

func tearDownEnv(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Tearing down e2e test environment")

		var err error

		for _, fn := range []env.Func{
			deleteNamespace(webhookNS, true),
			deleteNamespace(testNS, false),
			deleteKindCluster(clusterName),
		} {
			ctx, err = fn(ctx, cfg)
			if err != nil {
				return ctx, err
			}
		}
		return ctx, nil
	}
}

func TestValidation(t *testing.T) {
	testdata := os.DirFS("../testdata")

	install := features.New("Install webhook").
		Assess("webhook is installed with helm", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			repo, err := getDockerImageValue(ctx, dockerImageRepo)
			if err != nil {
				t.Fatal(err)
			}

			tag, err := getDockerImageValue(ctx, dockerImageTag)
			if err != nil {
				t.Fatal(err)
			}

			manager := helm.New(cfg.KubeconfigFile())
			err = manager.RunUpgrade(
				helm.WithName(helmInstallName),
				helm.WithNamespace(webhookNS),
				helm.WithChart(filepath.Join("..", "..", "helm", helmChartName)),
				helm.WithArgs("--set", "image.repository="+repo),
				helm.WithArgs("--set", "image.tag="+tag),
				helm.WithArgs("--install"),
				helm.WithWait(),
				helm.WithTimeout("2m"))
			if err != nil {
				t.Fatalf("failed to invoke helm install operation: %v", err)
			}

			return ctx
		}).
		Assess("deployment is running", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      helmInstallName + "-" + helmChartName,
					Namespace: webhookNS,
				},
				Spec: appsv1.DeploymentSpec{},
			}

			err := wait.For(
				conditions.New(cfg.Client().
					Resources(webhookNS)).
					ResourceScaled(deployment, func(object k8s.Object) int32 {
						return object.(*appsv1.Deployment).Status.ReadyReplicas
					}, 1))
			if err != nil {
				t.Fatal("failed waiting for the Deployment to reach a ready state")
			}

			return ctx
		}).Feature()

	admission := features.New("validate resource admission").
		Assess("insecure resources are rejected", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := resources.New(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatal(err)
			}

			for _, pattern := range []string{
				"daemonset-insecure.yaml",
				"deployment-insecure.yaml",
				"pod-insecure.yaml",
				"statefulset-insecure.yaml",
			} {
				err = decoder.DecodeEachFile(ctx, testdata, pattern,
					decoder.CreateHandler(r),
					decoder.MutateNamespace(testNS))
				if err == nil {
					t.Fatalf("no error occured, resource creation should not have worked: %s", pattern)
				}

				if !strings.Contains(err.Error(), "admission webhook \"admission.kubesec.io\" denied the request") {
					t.Errorf("resource creation should have because of the webhook deny, got different error: %v", err)
				}
			}
			return ctx
		}).
		Assess("hardened resources are accepted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := resources.New(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatal(err)
			}

			pattern := "*-hardened.yaml"
			err = decoder.DecodeEachFile(ctx, testdata, pattern,
				decoder.CreateHandler(r),
				decoder.MutateNamespace(testNS))
			if err != nil {
				t.Errorf("resource creation should have worked: %v", err)

				if strings.Contains(err.Error(), "admission webhook \"admission.kubesec.io\" denied the request") {
					t.Errorf("resource creation failed because of the webhook deny: %v", err)
				}
			}

			return ctx
		}).Feature()

	uninstall := features.New("Uninstall webhook").
		Assess("webhook is uninstalled with helm", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunUninstall(
				helm.WithName(helmInstallName),
				helm.WithNamespace(webhookNS),
				helm.WithWait(),
				helm.WithTimeout("2m"))
			if err != nil {
				t.Fatalf("failed to invoke helm uninstall operation: %v", err)
			}

			return ctx
		}).Feature()

	testenv.Test(t, install, admission, uninstall)
}
