/*
Copyright 2019 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package injection

import (
	"context"
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	"k8s.io/client-go/discovery"
	v2 "k8s.io/client-go/informers/autoscaling/v2"
	"k8s.io/client-go/informers/autoscaling/v2beta2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"knative.dev/pkg/controller"
	"knative.dev/serving/pkg/reconciler/autoscaling/hpakey"
)

// InformerInjector holds the type of a callback that attaches a particular
// informer type to a context.
type InformerInjector func(context.Context) (context.Context, controller.Informer)

// DynamicInformerInjector holds the type of a callback that attaches a particular
// informer type (backed by a Dynamic) to a context.
type DynamicInformerInjector func(context.Context) context.Context

// FilteredInformersInjector holds the type of a callback that attaches a set of particular
// filtered informers type to a context.
type FilteredInformersInjector func(context.Context) (context.Context, []controller.Informer)

func (i *impl) RegisterInformer(ii InformerInjector) {
	i.m.Lock()
	defer i.m.Unlock()

	i.informers = append(i.informers, ii)
}

func (i *impl) RegisterDynamicInformer(ii DynamicInformerInjector) {
	i.m.Lock()
	defer i.m.Unlock()

	i.dynamicInformers = append(i.dynamicInformers, ii)
}

func (i *impl) RegisterFilteredInformers(fii FilteredInformersInjector) {
	i.m.Lock()
	defer i.m.Unlock()

	i.filteredInformers = append(i.filteredInformers, fii)
}

func (i *impl) GetInformers() []InformerInjector {
	i.m.RLock()
	defer i.m.RUnlock()

	// Copy the slice before returning.
	return append(i.informers[:0:0], i.informers...)
}

func (i *impl) GetDynamicInformers() []DynamicInformerInjector {
	i.m.RLock()
	defer i.m.RUnlock()

	// Copy the slice before returning.
	return append(i.dynamicInformers[:0:0], i.dynamicInformers...)
}

func (i *impl) GetFilteredInformers() []FilteredInformersInjector {
	i.m.RLock()
	defer i.m.RUnlock()

	// Copy the slice before returning.
	return append(i.filteredInformers[:0:0], i.filteredInformers...)
}

func (i *impl) SetupDynamic(ctx context.Context) context.Context {
	// Based on the reconcilers we have linked, build up a set of clients and inject
	// them onto the context.
	for _, ci := range i.GetDynamicClients() {
		ctx = ci(ctx)
	}

	// Based on the reconcilers we have linked, build up a set of informers
	// and inject them onto the context.
	for _, ii := range i.GetDynamicInformers() {
		ctx = ii(ctx)
	}

	return ctx
}

func (i *impl) SetupInformers(ctx context.Context, cfg *rest.Config) (context.Context, []controller.Informer) {
	// Based on the reconcilers we have linked, build up a set of clients and inject
	// them onto the context.
	for _, ci := range i.GetClients() {
		ctx = ci(ctx, cfg)
	}

	// Based on the reconcilers we have linked, build up a set of informer factories
	// and inject them onto the context.
	for _, ifi := range i.GetInformerFactories() {
		ctx = ifi(ctx)
	}

	// Based on the reconcilers we have linked, build up a set of duck informer factories
	// and inject them onto the context.
	for _, duck := range i.GetDucks() {
		ctx = duck(ctx)
	}

	kc := kubernetes.NewForConfigOrDie(cfg)
	useHPAV2 := false
	if err := checkMinimumVersion(kc.Discovery(), "1.24.0"); err == nil {
		useHPAV2 = true
	}

	// Based on the reconcilers we have linked, build up a set of informers
	// and inject them onto the context.
	var inf controller.Informer
	var filteredinfs []controller.Informer
	informers := make([]controller.Informer, 0, len(i.GetInformers()))
	for _, ii := range i.GetInformers() {
		ctx, inf = ii(ctx)

		// We put the hpa informers on the context with a known key,
		// so we can avoid having both informers started.
		// The informer will still be on the context, but will not be run by the
		// calling function.
		hpaInf := ctx.Value(hpakey.IdentifiableKey{})
		if v2beta2Inf, ok := hpaInf.(v2beta2.HorizontalPodAutoscalerInformer); ok {
			if useHPAV2 && v2beta2Inf.Informer() == inf {
				continue
			}
		}

		if v2Inf, ok := hpaInf.(v2.HorizontalPodAutoscalerInformer); ok && !useHPAV2 {
			if !useHPAV2 && v2Inf.Informer() == inf {
				continue
			}
		}

		informers = append(informers, inf)
	}
	for _, fii := range i.GetFilteredInformers() {
		ctx, filteredinfs = fii(ctx)
		informers = append(informers, filteredinfs...)

	}
	return ctx, informers
}

type HPAV2Beta2Key struct{}

// using versionwrapper.CheckMinimumVersion will cause a cycle, thus
// this method is duplicated
func checkMinimumVersion(versioner discovery.ServerVersionInterface, version string) error {
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

// using versionwrapper.CheckMinimumVersion will cause a cycle, thus
// this method is duplicated
func normalizeVersion(v string) string {
	if strings.HasPrefix(v, "v") {
		// No need to account for unicode widths.
		return v[1:]
	}
	return v
}
