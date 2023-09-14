/*
Copyright 2022.

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

package controllers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/pem"
	oserrors "errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	trustbuilderv1 "github.com/att-cloudnative-labs/trustbuilder/api/v1"
)

const (
	TrustedCertificateAnnotation     = "trustbuilder.directv.com/trustedcertificate"
	CurrentCertificateHashAnnotation = "trustbuilder.directv.com/current-certificates-hash"
	ClusterCAFile                    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	DefaultStorePass                 = "changeit"
)

// CertificatePackageReconciler reconciles a CertificatePackage object
type CertificatePackageReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type PemCertificate struct {
	alias   string
	content []byte
}

type PemCertificateList []PemCertificate

//+kubebuilder:rbac:groups=trustbuilder.directv.com,resources=certificatepackages,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=trustbuilder.directv.com,resources=certificatepackages/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=trustbuilder.directv.com,resources=certificatepackages/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODx(user): Modify the Reconcile function to compare the state specified by
// the CertificatePackage object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *CertificatePackageReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("reconciling certificatePackage")

	var cp trustbuilderv1.CertificatePackage
	if err := r.Get(ctx, req.NamespacedName, &cp); err != nil {
		// If delete needs to be handled, check for ErrorNotFound here
		log.Info("object to be reconciled not found")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	pcl, err := r.getPemCertificateList(ctx, cp, log)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get pem certificate list: %s", err.Error())
	}

	expectedCertHash, err := getPemCertificateListHash(ctx, cp, pcl)
	log.V(2).Info(fmt.Sprintf("expected hash: %s", expectedCertHash))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get certificate list hash: %s", err.Error())
	}

	if ok, err := r.pclHashMatchesExpected(ctx, cp, expectedCertHash); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to compare existing certificate list hash %s", err.Error())
	} else if ok {
		log.Info(fmt.Sprintf("certificatePackage %s/%s is up to date. nothing to do", cp.Namespace, cp.Name))
		return ctrl.Result{}, nil
	}

	if err := r.reconcileTarget(ctx, cp, pcl, expectedCertHash); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile target: %s", err.Error())
	}

	return ctrl.Result{}, nil
}

func (r *CertificatePackageReconciler) getCertificateSecretsAndConfigMaps(ctx context.Context, cp trustbuilderv1.CertificatePackage, log logr.Logger) (v1.SecretList, v1.ConfigMapList, error) {
	var cmList v1.ConfigMapList
	var secList v1.SecretList

	sel, err := v12.LabelSelectorAsSelector(&cp.Spec.Selector)
	if err != nil {
		log.Error(err, "error converting LabelSelector to Selector", "namespace", cp.Namespace, "name", cp.Name)
		return v1.SecretList{}, v1.ConfigMapList{}, fmt.Errorf("error converting LabelSelector to Selector: %s", err.Error())
	}

	if err := r.List(ctx, &cmList, client.InNamespace(cp.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		log.Info("error retrieving configmaps for certificatePackage", "namespace", cp.Namespace, "name", cp.Name)
		return v1.SecretList{}, v1.ConfigMapList{}, err
	}

	if err := r.List(ctx, &secList, client.InNamespace(cp.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		log.Info("error retrieving secrets for certificatePackage", "namespace", cp.Namespace, "name", cp.Name)
		return v1.SecretList{}, v1.ConfigMapList{}, err
	}

	return secList, cmList, nil
}

func (r *CertificatePackageReconciler) getPemCertificateList(ctx context.Context, cp trustbuilderv1.CertificatePackage, log logr.Logger) (PemCertificateList, error) {
	pcl := make([]PemCertificate, 0)

	clusterCaSecretList, err := r.getClusterCaSecretList(ctx, log)
	if err != nil {
		return PemCertificateList{}, fmt.Errorf("failed to get cluster ca secrets: %s", err.Error())
	}

	secList, cmList, err := r.getCertificateSecretsAndConfigMaps(ctx, cp, log)
	if err != nil {
		return PemCertificateList{}, fmt.Errorf("failed to get secrets and configmaps: %s", err.Error())
	}
	// the configmaps and secrets must be processed in consistent order for hashing to be persistent
	// we must sort them by name into new arrays
	sort.Slice(cmList.Items, func(i, j int) bool {
		return cmList.Items[i].Name < cmList.Items[j].Name
	})
	sort.Slice(secList.Items, func(i, j int) bool {
		return secList.Items[i].Name < secList.Items[j].Name
	})
	sort.Slice(clusterCaSecretList.Items, func(i, j int) bool {
		return clusterCaSecretList.Items[i].Name < clusterCaSecretList.Items[j].Name
	})

	for _, sec := range secList.Items {
		if sCerts, err := getPemCertificatesFromSecret(sec, log); err != nil {
			return PemCertificateList{}, fmt.Errorf("failed to get pem certificates from secret: %s", err.Error())
		} else {
			pcl = append(pcl, sCerts...)
		}
	}

	for _, cm := range cmList.Items {
		if cmCerts, err := getPemCertificatesFromConfigMap(cm, log); err != nil {
			return PemCertificateList{}, fmt.Errorf("failed to get pem certificates from configmap: %s", err.Error())
		} else {
			pcl = append(pcl, cmCerts...)
		}
	}

	for _, casCert := range clusterCaSecretList.Items {
		if clusterCaSecCerts, err := getPemCertificatesFromSecret(casCert, log); err != nil {
			return PemCertificateList{}, fmt.Errorf("failed to get pem certificates from configmap: %s", err.Error())
		} else {
			pcl = append(pcl, clusterCaSecCerts...)
		}
	}

	return pcl, nil
}

func getPemCertificateListHash(ctx context.Context, cp trustbuilderv1.CertificatePackage, pcl PemCertificateList) (string, error) {
	log := logr.FromContext(ctx)
	log.V(2).Info(fmt.Sprintf("hashing pem certificate list with length: %d", len(pcl)))
	certBytes := make([]byte, 0)
	for _, pc := range pcl {
		log.V(3).Info(fmt.Sprintf("adding alias %s to certificate bytes array for hashing", pc.alias))
		certBytes = append(certBytes, pc.content...)
	}
	log.V(2).Info(fmt.Sprintf("hashing certificate byte array with length: %d", len(certBytes)))
	// we add the password secret and key so that changes to that update the has
	certBytes = append(certBytes, []byte(cp.Spec.PasswordSecret)...)
	certBytes = append(certBytes, []byte(cp.Spec.PasswordSecretKey)...)
	if hash, err := certHasher(certBytes); err != nil {
		return "", fmt.Errorf("failed to hash certificate: %s", err.Error())
	} else {
		return hex.EncodeToString(hash), nil
	}
}

func (r *CertificatePackageReconciler) pclHashMatchesExpected(ctx context.Context, cp trustbuilderv1.CertificatePackage, expectedHash string) (bool, error) {
	switch strings.ToLower(cp.Spec.ResourceType) {
	case "secret":
		secret, err := r.getTargetSecret(ctx, cp)
		if err != nil {
			return false, err
		}
		return expectedHash == getCertificateHashFromSecret(*secret), nil
	case "configmap":
		cm, err := r.getTargetConfigMap(ctx, cp)
		if err != nil {
			return false, err
		}
		return expectedHash == getCertificateHashFromConfigMap(*cm), nil
	default:
		return false, fmt.Errorf("invalid resource type, %s", cp.Spec.ResourceType)
	}
}

func (r *CertificatePackageReconciler) getTargetSecret(ctx context.Context, cp trustbuilderv1.CertificatePackage) (*v1.Secret, error) {
	var secret v1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: cp.Namespace, Name: cp.Spec.ResourceName}, &secret); err != nil {
		if errors.IsNotFound(err) {
			secret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   cp.Namespace,
					Name:        cp.Spec.ResourceName,
					Annotations: map[string]string{},
				},
				Data: map[string][]byte{},
			}
		} else if err != nil {
			return nil, fmt.Errorf("failed to get secret: %s", err.Error())
		}
	}
	return &secret, nil
}

func (r *CertificatePackageReconciler) getTargetConfigMap(ctx context.Context, cp trustbuilderv1.CertificatePackage) (*v1.ConfigMap, error) {
	var cm v1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: cp.Namespace, Name: cp.Spec.ResourceName}, &cm); err != nil {
		if errors.IsNotFound(err) {
			cm = v1.ConfigMap{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   cp.Namespace,
					Name:        cp.Spec.ResourceName,
					Annotations: map[string]string{},
				},
				Data: map[string]string{},
			}
		} else if err != nil {
			return nil, fmt.Errorf("failed to get configmap: %s", err.Error())
		}
	}
	return &cm, nil
}

func getCertificateHashFromSecret(secret v1.Secret) string {
	if secret.Annotations == nil {
		return ""
	}
	if hash, ok := secret.Annotations[CurrentCertificateHashAnnotation]; !ok {
		return ""
	} else {
		return hash
	}
}

func getCertificateHashFromConfigMap(cm v1.ConfigMap) string {
	if cm.Annotations == nil {
		return ""
	}
	if hash, ok := cm.Annotations[CurrentCertificateHashAnnotation]; !ok {
		return ""
	} else {
		return hash
	}
}

func getClusterCAPemCertificate(log logr.Logger) (*PemCertificate, error) {
	certData := make([]byte, 0)
	if _, err := os.Stat(ClusterCAFile); oserrors.Is(err, os.ErrNotExist) {
		log.Info("cluster CA file not present. skipping")
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed checking for cluster ca file: %s", err.Error())
	}

	f, err := os.Open(ClusterCAFile)
	if err != nil {
		return nil, fmt.Errorf("error opening cluster ca file: %s", err.Error())
	}
	reader := bufio.NewReader(f)
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading cluster ca file: %s", err.Error())
	}
	certData = append(certData, content...)
	return &PemCertificate{alias: "cluster-ca", content: certData}, nil
}

func (r *CertificatePackageReconciler) getClusterCaSecretList(ctx context.Context, log logr.Logger) (v1.SecretList, error) {
	var secList v1.SecretList

	labelSelector := v12.LabelSelector{MatchLabels: map[string]string{"trustbuilder-global": "cluster-ca"}}

	sel, err := v12.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		log.Error(err, "error converting LabelSelector to Selector", "namespace", "global-trust-certificates", "name", "cluster-ca")
		return v1.SecretList{}, fmt.Errorf("error converting LabelSelector to Selector: %s", err.Error())
	}

	if err := r.List(ctx, &secList, client.InNamespace("global-trust-certificates"), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		log.Info("error retrieving secrets for certificatePackage", "namespace", "global-trust-certificates", "name", "cluster-ca")
		return v1.SecretList{}, err
	}

	return secList, nil
}

func getPemCertificatesFromConfigMap(cm v1.ConfigMap, log logr.Logger) (PemCertificateList, error) {
	pcl := make([]PemCertificate, 0)
	if cm.Annotations == nil || strings.ToLower(cm.Annotations[TrustedCertificateAnnotation]) != "true" {
		log.Info(fmt.Sprintf("configmap %s/%s does not have required annotation for containing trusted certificates", cm.Namespace, cm.Name))
		return pcl, nil
	}
	if cm.Data == nil {
		log.Info(fmt.Sprintf("configmap %s/%s does not does not contain any data", cm.Namespace, cm.Name))
		return pcl, nil
	}
	for k, v := range cm.Data {
		pcl = append(pcl, PemCertificate{alias: k, content: []byte(v)})
	}
	return pcl, nil
}

func getPemCertificatesFromSecret(secret v1.Secret, log logr.Logger) (PemCertificateList, error) {
	pcl := make([]PemCertificate, 0)
	if secret.Annotations == nil || strings.ToLower(secret.Annotations[TrustedCertificateAnnotation]) != "true" {
		log.Info(fmt.Sprintf("secret %s/%s does not have required annotation for containing trusted certificates", secret.Namespace, secret.Name))
		return pcl, nil
	}
	if secret.Data == nil {
		log.Info(fmt.Sprintf("secret %s/%s does not does not contain any data", secret.Namespace, secret.Name))
		return pcl, nil
	}
	for k, v := range secret.Data {
		pcl = append(pcl, PemCertificate{alias: k, content: v})
	}
	return pcl, nil
}

func (r *CertificatePackageReconciler) reconcileTarget(ctx context.Context, cp trustbuilderv1.CertificatePackage, pcl PemCertificateList, expectedCertHash string) error {
	switch strings.ToLower(cp.Spec.PackageType) {
	case "jks":
		return r.reconcileJKSTarget(ctx, cp, pcl, expectedCertHash)
	case "pem":
		return r.reconcilePemTarget(ctx, cp, pcl, expectedCertHash)
	default:
		return fmt.Errorf("unsupported package type, %s", cp.Spec.PackageType)
	}
}

func (r *CertificatePackageReconciler) reconcileJKSTarget(ctx context.Context, cp trustbuilderv1.CertificatePackage, pcl PemCertificateList, expectedCertHash string) error {
	// Build truststore
	ks := keystore.New()
	var keystoreBytes []byte
	for _, pc := range pcl {
		if err := addPemCertificateToJKSKeystore(ks, pc); err != nil {
			return fmt.Errorf("failed to add pem certificate to keystore: %s", err.Error())
		}
	}
	buf := new(bytes.Buffer)
	storepass, ok, err := r.getStorePassword(ctx, cp)
	if err != nil {
		return fmt.Errorf("failed to get store password: %s", err.Error())
	} else if !ok {
		return fmt.Errorf("jks format requires a password")
	}
	if err := ks.Store(buf, []byte(storepass)); err != nil {
		return fmt.Errorf("failed to store keystore bytes: %s", err.Error())
	}

	keystoreBytes = buf.Bytes()
	switch strings.ToLower(cp.Spec.ResourceType) {
	case "secret":
		if err := r.applyCertBytesToSecret(ctx, cp, keystoreBytes, expectedCertHash); err != nil {
			return fmt.Errorf("failed to apply certificate bytes to secret: %s", err.Error())
		}
	default:
		return fmt.Errorf("unsupported resource type, %s", cp.Spec.ResourceType)
	}
	return nil
}

func (r *CertificatePackageReconciler) reconcilePemTarget(ctx context.Context, cp trustbuilderv1.CertificatePackage, pcl PemCertificateList, expectedCertHash string) error {
	// Build pem
	certBytes := make([]byte, 0)
	for _, pc := range pcl {
		certBytes = append(certBytes, []byte(pc.alias)...)
		certBytes = append(certBytes, []byte("\n")...)
		certBytes = append(certBytes, pc.content...)
		certBytes = append(certBytes, []byte("\n")...)
	}
	switch strings.ToLower(cp.Spec.ResourceType) {
	case "secret":
		if err := r.applyCertBytesToSecret(ctx, cp, certBytes, expectedCertHash); err != nil {
			return fmt.Errorf("failed to apply certificate bytes to secret: %s", err.Error())
		}
	default:
		return fmt.Errorf("unsupported resource type, %s", cp.Spec.ResourceType)
	}
	return nil
}

func (r *CertificatePackageReconciler) applyCertBytesToSecret(ctx context.Context, cp trustbuilderv1.CertificatePackage, dataBytes []byte, certHash string) error {
	var targetSecret v1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: cp.Namespace, Name: cp.Spec.ResourceName}, &targetSecret); err != nil {
		if errors.IsNotFound(err) {
			targetSecret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace: cp.Namespace,
					Name:      cp.Spec.ResourceName,
				},
			}
		} else {
			return fmt.Errorf("failed to get destination secret: %s", err.Error())
		}
	}
	if targetSecret.Annotations == nil {
		targetSecret.Annotations = map[string]string{}
	}
	targetSecret.Annotations[CurrentCertificateHashAnnotation] = certHash
	if targetSecret.Data == nil {
		targetSecret.Data = map[string][]byte{}
	}
	targetSecret.Data[cp.Spec.Key] = dataBytes

	if err := r.applySecret(ctx, &targetSecret); err != nil {
		return fmt.Errorf("failed to update or create secret: %s", err.Error())
	}
	return nil
}

func addPemCertificateToJKSKeystore(ks keystore.KeyStore, pc PemCertificate) error {
	rest := pc.content
	blockCount := 0
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		cert := keystore.Certificate{
			Type:    "X509",
			Content: block.Bytes,
		}
		tce := keystore.TrustedCertificateEntry{
			CreationTime: time.Time{},
			Certificate:  cert,
		}
		alias := pc.alias
		if blockCount > 0 {
			alias = pc.alias + "-" + strconv.Itoa(blockCount)
		}
		err := ks.SetTrustedCertificateEntry(alias, tce)
		if err != nil {
			return fmt.Errorf("failed to set trusted certificate entry, %s: %s", alias, err.Error())
		}
		rest = remainder
		blockCount++
	}
	return nil
}

func (r *CertificatePackageReconciler) applySecret(ctx context.Context, secret *v1.Secret) error {
	var currSecret v1.Secret
	currExists := true

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}, &currSecret); err != nil {
			if errors.IsNotFound(err) {
				currExists = false
			} else {
				return fmt.Errorf("error getting current secret: %s/%s, %s", secret.Namespace, secret.Name, err.Error())
			}
		} else {
			secret.ResourceVersion = currSecret.ResourceVersion
		}
		if currExists {
			return r.Update(ctx, secret)
		}
		return r.Create(ctx, secret)
	})

	return retryErr
}

func (r *CertificatePackageReconciler) getStorePassword(ctx context.Context, cp trustbuilderv1.CertificatePackage) (string, bool, error) {
	storepass := DefaultStorePass
	if len(cp.Spec.PasswordSecret) > 0 {
		var pwSecret v1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: cp.Namespace, Name: cp.Spec.PasswordSecret}, &pwSecret); err != nil {
			return "", false, fmt.Errorf("error retrieving indicated store password secret: %s", err.Error())
		}
		pwKey := ""
		if len(cp.Spec.PasswordSecretKey) > 0 {
			pwKey = cp.Spec.PasswordSecretKey
		}
		if len(pwKey) > 0 {
			if pwSecret.Data == nil {
				return "", false, fmt.Errorf("password secret key indicated does not exists")
			}
			if val, ok := pwSecret.Data[pwKey]; !ok {
				return "", false, fmt.Errorf("password secret key indicated does not exists")
			} else {
				storepass = string(val)
			}
		} else {
			return "", false, fmt.Errorf("password secret key must be defined if password secret is defined")
		}
	} else {
		return "", false, nil
	}
	return storepass, true, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificatePackageReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&trustbuilderv1.CertificatePackage{}).
		Complete(r)
}
