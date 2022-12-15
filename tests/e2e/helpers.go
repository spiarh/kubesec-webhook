package e2e

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

func createKindCluster(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Creating Kind cluster", "cluster-name", clusterName)
		return envfuncs.CreateKindCluster(clusterName)(ctx, cfg)
	}
}

func deleteKindCluster(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Deleting Kind cluster", "cluster-name", clusterName)
		return envfuncs.DestroyKindCluster(clusterName)(ctx, cfg)
	}
}

// createNamespace is a wrapper to add logging
// and wait for the namespace to be created.
func createNamespace(name string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Creating namespace", "namespace", name)

		ctx, err := envfuncs.CreateNamespace(name)(ctx, cfg)
		if err != nil {
			return ctx, err
		}

		klog.InfoS("Waiting for namespace to be created", "namespace", name)
		ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		err = wait.For(
			conditions.New(cfg.Client().Resources(name)).
				ResourceMatch(ns, func(object k8s.Object) bool {
					return true
				}))
		if err != nil {
			return ctx, fmt.Errorf("failed waiting for the namespace to be created: %w", err)
		}

		return ctx, nil
	}
}

// deleteNamespace is a wrapper to add logging
// and wait if enabled for the namespace to be deleted.
func deleteNamespace(name string, ensureDeleted bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Deleting namespace", "namespace", name)

		ctx, err := envfuncs.DeleteNamespace(name)(ctx, cfg)
		if err != nil {
			return ctx, err
		}

		if ensureDeleted {
			klog.InfoS("Waiting for namespace to be deleted", "namespace", name)
			ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
			err = wait.For(
				conditions.New(cfg.Client().Resources(name)).
					ResourceDeleted(ns))
			if err != nil {
				return ctx, fmt.Errorf("failed waiting for the namespace to be deleted: %w", err)
			}
		}

		return ctx, nil
	}
}

func enableValidationOnNS(name string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		klog.InfoS("Enabling webhook validation on test namespace")
		// TODO: test to get the NS from context
		obj := v1.Namespace{}
		err := cfg.Client().Resources().Get(ctx, name, "", &obj)
		if err != nil {
			return ctx, nil
		}

		obj.SetLabels(map[string]string{"kubesec-validation": "enabled"})

		return ctx, cfg.Client().Resources().Update(ctx, &obj)
	}
}
