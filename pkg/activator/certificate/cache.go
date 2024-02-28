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

package certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	"knative.dev/networking/pkg/certificates"
	netcfg "knative.dev/networking/pkg/config"
	"knative.dev/pkg/controller"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
)

// CertCache caches certificates and CA pool.
type CertCache struct {
	secretInformer v1.SecretInformer
	logger         *zap.SugaredLogger

	certificate *tls.Certificate
	TLSConf     tls.Config

	ticker *time.Ticker
	stop   chan struct{}

	certificatesMux sync.RWMutex
}

// NewCertCache creates and starts the certificate cache that watches Activators certificate.
func NewCertCache(ctx context.Context) (*CertCache, error) {
	secretInformer := secretinformer.Get(ctx)

	cr := &CertCache{
		secretInformer: secretInformer,
		logger:         logging.FromContext(ctx),
		ticker:         time.NewTicker(5 * time.Second),
		stop:           make(chan struct{}),
	}

	secret, err := cr.secretInformer.Lister().Secrets(system.Namespace()).Get(netcfg.ServingRoutingCertName)
	if err != nil {
		return nil, fmt.Errorf("failed to get activator certificate, secret %s/%s was not found: %w. Enabling system-internal-tls requires the secret to be present and populated with a valid certificate",
			system.Namespace(), netcfg.ServingRoutingCertName, err)
	}

	cr.updateCertificate(secret)

	secretInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.FilterWithNameAndNamespace(system.Namespace(), netcfg.ServingRoutingCertName),
		Handler: cache.ResourceEventHandlerFuncs{
			UpdateFunc: cr.handleCertificateUpdate,
			AddFunc:    cr.handleCertificateAdd,
		},
	})

	go cr.watch()

	return cr, nil
}

// Stop shuts down the CertCache. Use this with `defer`.
func (cr *CertCache) Stop() {
	cr.logger.Info("Stopping certificate cache")
	close(cr.stop)
	cr.ticker.Stop()
}

func (cr *CertCache) watch() {
	for {
		select {
		case <-cr.stop:
			return

		case <-cr.ticker.C:
			// On error, we do not want to stop trying
			if err := cr.refreshSystemCertPool(); err != nil {
				cr.logger.Error(err)
			}
		}
	}
}

func (cr *CertCache) handleCertificateAdd(added interface{}) {
	if secret, ok := added.(*corev1.Secret); ok {
		cr.updateCertificate(secret)
	}
}

func (cr *CertCache) handleCertificateUpdate(_, new interface{}) {
	cr.handleCertificateAdd(new)
}

func (cr *CertCache) updateCertificate(secret *corev1.Secret) {
	cr.certificatesMux.Lock()
	defer cr.certificatesMux.Unlock()

	cert, err := tls.X509KeyPair(secret.Data[certificates.CertName], secret.Data[certificates.PrivateKeyName])
	if err != nil {
		cr.logger.Warnf("failed to parse certificate in secret %s/%s: %v", secret.Namespace, secret.Name, zap.Error(err))
		return
	}
	cr.certificate = &cert
}

func (cr *CertCache) refreshSystemCertPool() error {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	// Use the trust pool in upstream TLS context
	cr.certificatesMux.Lock()
	defer cr.certificatesMux.Unlock()

	s := ""
	for _, c := range pool.Subjects() {
		s += string(c) + ", "
	}
	cr.logger.Infof("updating system cert pool: %s", s)

	cr.TLSConf.RootCAs = pool
	cr.TLSConf.ServerName = certificates.LegacyFakeDnsName
	cr.TLSConf.MinVersion = tls.VersionTLS13

	return nil
}

//func (cr *CertCache) updateCache(secret *corev1.Secret) {
//	cr.certificatesMux.Lock()
//	defer cr.certificatesMux.Unlock()
//
//	cert, err := tls.X509KeyPair(secret.Data[certificates.CertName], secret.Data[certificates.PrivateKeyName])
//	if err != nil {
//		cr.logger.Warnw("failed to parse secret", zap.Error(err))
//		return
//	}
//	cr.certificate = &cert
//
//	pool := x509.NewCertPool()
//	block, _ := pem.Decode(secret.Data[certificates.CaCertName])
//	ca, err := x509.ParseCertificate(block.Bytes)
//	if err != nil {
//		cr.logger.Warnw("failed to parse CA", zap.Error(err))
//		return
//	}
//	pool.AddCert(ca)
//
//	cr.TLSConf.RootCAs = pool
//	cr.TLSConf.ServerName = certificates.LegacyFakeDnsName
//	cr.TLSConf.MinVersion = tls.VersionTLS13
//}

// GetCertificate returns the cached certificates.
func (cr *CertCache) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cr.certificate, nil
}
