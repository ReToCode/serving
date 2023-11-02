//go:build e2e
// +build e2e

/*
Copyright 2023 The Knative Authors

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

package clusterlocaldomaintls

import (
	"context"
	"net/url"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netapi "knative.dev/networking/pkg/apis/networking"
	"knative.dev/networking/pkg/certificates"
	"knative.dev/pkg/system"
	"knative.dev/serving/pkg/apis/serving"
	rtesting "knative.dev/serving/pkg/testing/v1"
	"knative.dev/serving/test"
	"knative.dev/serving/test/e2e"
	v1test "knative.dev/serving/test/v1"
)

var dnsVariants = []struct {
	name   string
	suffix string
}{
	{"fqdn", ""},
	{"short", ".cluster.local"},
	{"shortest", ".svc.cluster.local"},
}

func TestClusterLocalDomainTLSClusterLocalVisibility(t *testing.T) {
	if !test.ServingFlags.EnableAlphaFeatures {
		t.Skip("Alpha features not enabled")
	}

	if !(strings.Contains(test.ServingFlags.IngressClass, "kourier")) {
		t.Skip("Skip this test for non-kourier ingress.")
	}

	t.Parallel()
	clients := test.Setup(t)
	names := test.ResourceNames{
		Service: test.ObjectNameForTest(t),
		Image:   test.HelloWorld,
	}

	test.EnsureTearDown(t, clients, &names)

	withInternalVisibility := rtesting.WithServiceLabel(netapi.VisibilityLabelKey, serving.VisibilityClusterLocal)
	t.Log("Creating a new service with cluster-local visibility")
	resources, err := v1test.CreateServiceReady(t, clients, &names, withInternalVisibility)
	if err != nil {
		t.Fatalf("Failed to create initial Service: %v: %v", names.Service, err)
	}

	// After the service is created, we need to wait for the CA to be populated,
	// then use that secret in the ProxyImage to trust the cluster-local https connection
	secret, err := e2e.GetCASecret(clients)
	if err != nil {
		t.Fatal(err.Error())
	}

	svcUrl := resources.Route.Status.URL.URL()
	if svcUrl.Scheme != "https" {
		t.Fatalf("URL scheme of service %v was not https", names.Service)
	}

	// Check access via https on all cluster-local-domains
	for _, dns := range dnsVariants {
		helloworldURL := &url.URL{
			Scheme: svcUrl.Scheme,
			Host:   strings.TrimSuffix(svcUrl.Host, dns.suffix),
			Path:   svcUrl.Path,
		}
		t.Run(dns.name, func(t *testing.T) {
			t.Parallel()
			e2e.TestProxyToHelloworld(t, clients, helloworldURL, false, false, secret)
		})
	}
}

func TestClusterLocalDomainTLSClusterExternalVisibility(t *testing.T) {
	if !test.ServingFlags.EnableAlphaFeatures {
		t.Skip("Alpha features not enabled")
	}

	if !(strings.Contains(test.ServingFlags.IngressClass, "kourier")) {
		t.Skip("Skip this test for non-kourier ingress.")
	}

	t.Parallel()
	clients := test.Setup(t)
	names := test.ResourceNames{
		Service: test.ObjectNameForTest(t),
		Image:   test.HelloWorld,
	}

	test.EnsureTearDown(t, clients, &names)

	t.Log("Creating a new service with external visibility")
	resources, err := v1test.CreateServiceReady(t, clients, &names)
	if err != nil {
		t.Fatalf("Failed to create initial Service: %v: %v", names.Service, err)
	}

	// After the service is created, we need to wait for the CA to be populated,
	// then use that secret in the ProxyImage to trust the cluster-local https connection
	secret, err := e2e.GetCASecret(clients)
	if err != nil {
		t.Fatal(err.Error())
	}

	externalURL := resources.Route.Status.URL.URL()
	internalURL := resources.Route.Status.Address.URL

	if internalURL.Scheme != "https" {
		t.Fatalf("Internal URL scheme of service %v was not https", names.Service)
	}

	if externalURL.Scheme != "http" {
		t.Fatalf("External URL scheme of service %v was not http", names.Service)
	}

	// Check normal access on external domain
	t.Run("external-access", func(t *testing.T) {
		t.Parallel()
		e2e.TestProxyToHelloworld(t, clients, externalURL, false, true, secret)
	})

	// Check access via https on all cluster-local-domains
	for _, dns := range dnsVariants {
		helloworldURL := &url.URL{
			Scheme: internalURL.Scheme,
			Host:   strings.TrimSuffix(internalURL.Host, dns.suffix),
			Path:   internalURL.Path,
		}
		t.Run(dns.name, func(t *testing.T) {
			t.Parallel()
			e2e.TestProxyToHelloworld(t, clients, helloworldURL, false, false, secret)
		})
	}
}

func TestClusterLocalDomainTLSCARotation(t *testing.T) {
	if !test.ServingFlags.EnableAlphaFeatures {
		t.Skip("Alpha features not enabled")
	}

	if !(strings.Contains(test.ServingFlags.IngressClass, "kourier")) {
		t.Skip("Skip this test for non-kourier ingress.")
	}

	clients := test.Setup(t)
	names := test.ResourceNames{
		Service: test.ObjectNameForTest(t),
		Image:   test.HelloWorld,
	}

	test.EnsureTearDown(t, clients, &names)

	t.Log("Creating a new service with cluster-local visibility")
	ctx := context.Background()
	withInternalVisibility := rtesting.WithServiceLabel(netapi.VisibilityLabelKey, serving.VisibilityClusterLocal)
	resources, err := v1test.CreateServiceReady(t, clients, &names, withInternalVisibility)
	if err != nil {
		t.Fatalf("Failed to create initial Service: %v: %v", names.Service, err)
	}

	// After the service is created, we need to wait for the CA to be populated,
	// then use that secret in the ProxyImage to trust the cluster-local https connection
	secret, err := e2e.GetCASecret(clients)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Check access via https on all cluster-local-domains
	svcUrl := resources.Route.Status.URL.URL()
	for _, dns := range dnsVariants {
		helloworldURL := &url.URL{
			Scheme: svcUrl.Scheme,
			Host:   strings.TrimSuffix(svcUrl.Host, dns.suffix),
			Path:   svcUrl.Path,
		}
		t.Run(dns.name+"-old-ca", func(t *testing.T) {
			e2e.TestProxyToHelloworld(t, clients, helloworldURL, false, false, secret)
		})
	}

	// TODO: move this to encryption.go
	// Trigger a CA rotation by modifying the CA secret in SYSTEM_NAMESPACE
	caSecret, err := clients.KubeClient.CoreV1().Secrets(system.Namespace()).Get(ctx, e2e.KnativeCASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get existing Knative self-signed CA secret %s/%s: %v", system.Namespace(), e2e.KnativeCASecretName, err)
	}

	// dropping the values will re-populate them and fire the reconciler for all KnativeCertificates
	caSecret.Data[certificates.CertName] = nil
	caSecret.Data[certificates.PrivateKeyName] = nil

	_, err = clients.KubeClient.CoreV1().Secrets(system.Namespace()).Update(ctx, caSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Could not update CA secret %s/%s: %v", system.Namespace(), e2e.KnativeCASecretName, err)
	}

	// After the service is created, we need to wait for the CA to be populated,
	// then use that secret in the ProxyImage to trust the cluster-local https connection
	newSecret, err := e2e.GetCASecret(clients)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Re-run the access test via https on all cluster-local-domains
	// using the new CA to verify trust to the backing service
	for _, dns := range dnsVariants {
		helloworldURL := &url.URL{
			Scheme: svcUrl.Scheme,
			Host:   strings.TrimSuffix(svcUrl.Host, dns.suffix),
			Path:   svcUrl.Path,
		}
		t.Run(dns.name+"-new-ca", func(t *testing.T) {
			e2e.TestProxyToHelloworld(t, clients, helloworldURL, false, false, newSecret)
		})
	}
}
