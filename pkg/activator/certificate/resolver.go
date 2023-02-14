package certificate

import (
	"context"
	"crypto/tls"
	"sync"

	"go.uber.org/zap"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"knative.dev/control-protocol/pkg/certificates"
	"knative.dev/networking/pkg/apis/networking"
	"knative.dev/networking/pkg/apis/networking/v1alpha1"
	kcertinformer "knative.dev/networking/pkg/client/injection/informers/networking/v1alpha1/certificate"
	secretfilteredinformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret/filtered"
	filteredFactory "knative.dev/pkg/client/injection/kube/informers/factory/filtered"
	"knative.dev/pkg/logging"
	pkgreconciler "knative.dev/pkg/reconciler"
)

const (
	defaultCertificateDomain = "knative"
)

type CertResolver struct {
	secretInformer v1.SecretInformer
	logger         *zap.SugaredLogger

	certificates    map[string]*tls.Certificate
	certificatesMux sync.RWMutex
}

func NewCertResolver(ctx context.Context) *CertResolver {
	knCertificateInformer := kcertinformer.Get(ctx)
	secretInformer := getSecretInformer(ctx)

	cr := &CertResolver{
		secretInformer: secretInformer,
		certificates:   make(map[string]*tls.Certificate),
		logger:         logging.FromContext(ctx),
	}

	knCertificateInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		// TODO: update the filter if we have a custom label for internal certs
		FilterFunc: pkgreconciler.LabelExistsFilterFunc(networking.VisibilityLabelKey),
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    cr.handleCertificateAdd,
			UpdateFunc: cr.handleCertificateUpdate,
			DeleteFunc: cr.handleCertificateDelete,
		},
	})

	return cr
}

// GetCertificate returns a certificate based on SNIs ClientHello.
// If we return (nil, error) the client sees - 'tls: internal error'
// If we return (nil, nil) the client sees - 'tls: no certificates configured'
// We'll return (nil, nil) when we don't find a certificate
func (cr *CertResolver) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.certificatesMux.RLock()
	defer cr.certificatesMux.RUnlock()

	if crt, ok := cr.certificates[info.ServerName]; ok {
		cr.logger.Warnw("SNI request, returning domain cert", zap.String("server-name", info.ServerName))
		return crt, nil
	}

	// Fallback to default certificate with SAN = defaultCertificateDomain
	if crt, ok := cr.certificates[defaultCertificateDomain]; ok {
		cr.logger.Warnw("SNI request, returning DEFAULT", zap.String("server-name", info.ServerName))
		return crt, nil
	}

	cr.logger.Warnw("SNI request, returning NO CERT", zap.String("server-name", info.ServerName))

	return nil, nil
}

func (cr *CertResolver) handleCertificateAdd(added interface{}) {
	if kCert, ok := added.(*v1alpha1.Certificate); ok {
		secret, err := cr.secretInformer.Lister().Secrets(kCert.Namespace).Get(kCert.Spec.SecretName)
		if err != nil {
			cr.logger.Warnw("failed to get secret", zap.Namespace(kCert.Namespace), zap.Error(err))
			return
		}
		cr.certificatesMux.Lock()
		defer cr.certificatesMux.Unlock()

		cert, err := tls.X509KeyPair(secret.Data[certificates.CertName], secret.Data[certificates.PrivateKeyName])
		if err != nil {
			cr.logger.Warnw("failed to parse secret", zap.Namespace(kCert.Namespace), zap.Error(err))
			return
		}

		for _, domain := range kCert.Spec.DNSNames {
			cr.certificates[domain] = &cert
		}
	}
}

func (cr *CertResolver) handleCertificateUpdate(old, new interface{}) {
	cr.handleCertificateDelete(old)
	cr.handleCertificateAdd(new)
}

func (cr *CertResolver) handleCertificateDelete(del interface{}) {
	if kCert, ok := del.(*v1alpha1.Certificate); ok {
		cr.certificatesMux.Lock()
		defer cr.certificatesMux.Unlock()

		for _, domain := range kCert.Spec.DNSNames {
			delete(cr.certificates, domain)
		}
	}
}

func getSecretInformer(ctx context.Context) v1.SecretInformer {
	untyped := ctx.Value(filteredFactory.LabelKey{}) // This should always be not nil and have exactly one selector
	return secretfilteredinformer.Get(ctx, untyped.([]string)[0])
}
