/*
Copyright 2022 The Knative Authors

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

// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"
	"time"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	scheme "knative.dev/serving/pkg/client/certmanager/clientset/versioned/scheme"
)

// ClusterIssuersGetter has a method to return a ClusterIssuerInterface.
// A group's client should implement this interface.
type ClusterIssuersGetter interface {
	ClusterIssuers() ClusterIssuerInterface
}

// ClusterIssuerInterface has methods to work with ClusterIssuer resources.
type ClusterIssuerInterface interface {
	Create(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.CreateOptions) (*v1.ClusterIssuer, error)
	Update(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.UpdateOptions) (*v1.ClusterIssuer, error)
	UpdateStatus(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.UpdateOptions) (*v1.ClusterIssuer, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.ClusterIssuer, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.ClusterIssuerList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ClusterIssuer, err error)
	ClusterIssuerExpansion
}

// clusterIssuers implements ClusterIssuerInterface
type clusterIssuers struct {
	client rest.Interface
}

// newClusterIssuers returns a ClusterIssuers
func newClusterIssuers(c *CertmanagerV1Client) *clusterIssuers {
	return &clusterIssuers{
		client: c.RESTClient(),
	}
}

// Get takes name of the clusterIssuer, and returns the corresponding clusterIssuer object, and an error if there is any.
func (c *clusterIssuers) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ClusterIssuer, err error) {
	result = &v1.ClusterIssuer{}
	err = c.client.Get().
		Resource("clusterissuers").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ClusterIssuers that match those selectors.
func (c *clusterIssuers) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ClusterIssuerList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.ClusterIssuerList{}
	err = c.client.Get().
		Resource("clusterissuers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested clusterIssuers.
func (c *clusterIssuers) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("clusterissuers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a clusterIssuer and creates it.  Returns the server's representation of the clusterIssuer, and an error, if there is any.
func (c *clusterIssuers) Create(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.CreateOptions) (result *v1.ClusterIssuer, err error) {
	result = &v1.ClusterIssuer{}
	err = c.client.Post().
		Resource("clusterissuers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterIssuer).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a clusterIssuer and updates it. Returns the server's representation of the clusterIssuer, and an error, if there is any.
func (c *clusterIssuers) Update(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.UpdateOptions) (result *v1.ClusterIssuer, err error) {
	result = &v1.ClusterIssuer{}
	err = c.client.Put().
		Resource("clusterissuers").
		Name(clusterIssuer.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterIssuer).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *clusterIssuers) UpdateStatus(ctx context.Context, clusterIssuer *v1.ClusterIssuer, opts metav1.UpdateOptions) (result *v1.ClusterIssuer, err error) {
	result = &v1.ClusterIssuer{}
	err = c.client.Put().
		Resource("clusterissuers").
		Name(clusterIssuer.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterIssuer).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the clusterIssuer and deletes it. Returns an error if one occurs.
func (c *clusterIssuers) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Resource("clusterissuers").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *clusterIssuers) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("clusterissuers").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched clusterIssuer.
func (c *clusterIssuers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ClusterIssuer, err error) {
	result = &v1.ClusterIssuer{}
	err = c.client.Patch(pt).
		Resource("clusterissuers").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
