package versionwrapper

import (
	"context"
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	"k8s.io/client-go/discovery"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/serving/pkg/reconciler/autoscaling/hpa"
	hpav2beta2 "knative.dev/serving/pkg/reconciler/autoscaling/hpav2beta2"
)

func NewController(
	ctx context.Context,
	cmw configmap.Watcher,
) *controller.Impl {
	kc := kubeclient.Get(ctx)
	// Starting from 4.10 (1.24.0) we can use the new API version (autoscaling/v2) of HorizontalPodAutoscaler
	// As we also need to support 4.8 we also need provide the controller using the old API version (autoscaling/v2beta2)
	if err := CheckMinimumVersion(kc.Discovery(), "1.24.0"); err == nil {
		fmt.Println("Running hpa.NewContoller")
		return hpa.NewController(ctx, cmw)
	} else {
		fmt.Println("Running hpav2beta2.NewContoller")
		return hpav2beta2.NewController(ctx, cmw)
	}
}

// CheckMinimumVersion checks if current K8s version we are on is higher than the one passed.
// An error is returned if the version is lower.
// Based on implementation in SO: https://github.com/openshift-knative/serverless-operator/blob/main/openshift-knative-operator/pkg/common/api.go#L134
func CheckMinimumVersion(versioner discovery.ServerVersionInterface, version string) error {
	v, err := versioner.ServerVersion()
	if err != nil {
		return err
	}
	currentVersion, err := semver.Make(normalizeVersion(v.GitVersion))
	if err != nil {
		return err
	}

	minimumVersion, err := semver.Make(normalizeVersion(version))
	if err != nil {
		return err
	}

	// If no specific pre-release requirement is set, we default to "-0" to always allow
	// pre-release versions of the same Major.Minor.Patch version.
	if len(minimumVersion.Pre) == 0 {
		minimumVersion.Pre = []semver.PRVersion{{VersionNum: 0, IsNum: true}}
	}

	if currentVersion.LT(minimumVersion) {
		return fmt.Errorf("kubernetes version %q is not compatible, need at least %q",
			currentVersion, minimumVersion)
	}
	return nil
}

func normalizeVersion(v string) string {
	if strings.HasPrefix(v, "v") {
		// No need to account for unicode widths.
		return v[1:]
	}
	return v
}
