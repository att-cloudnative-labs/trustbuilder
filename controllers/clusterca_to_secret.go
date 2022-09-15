package controllers

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	ClusterCaSecretPrefix = "cluster-ca-"
)

func ClusterCaToSecret(client client.Client, ctx context.Context, namespace string, channel chan struct{}) error {
	log := log.FromContext(ctx)

	ticker := time.NewTicker(20 * time.Second)
	for {
		select {
		case <-ticker.C:

			Namespace, err := createNameSpaceIfNotPresent(ctx, log, client, namespace)
			if err != nil {
				log.Error(fmt.Errorf(err.Error()), "failed create/get namespace: %s", namespace)
				break
			}

			clusterCert, err := getCert(log)
			if err != nil {
				log.Error(fmt.Errorf(err.Error()), "failed to get cluster ca")
				break
			}

			clusterCAPemCertHash, err := getPemCertificateHash(*clusterCert, log)
			if err != nil {
				log.Error(fmt.Errorf(err.Error()), "failed to get cluster CA Hash")
				break
			}

			var secretNameWithHash = ClusterCaSecretPrefix + clusterCAPemCertHash[27:32]

			Secret, isSecretPresent, err := checkIfSecretPresent(ctx, client, log, Namespace.Name, secretNameWithHash)
			if err != nil {
				log.Error(fmt.Errorf(err.Error()), "failed to check if secret is present")
				break
			}

			if isSecretPresent {

				if clusterCAPemCertHash == getCertificateHashFromSecret(*Secret) {
					log.Info("Cert and Secret Hash Match, do nothing...")
					break
				} else {
					log.Info("Cert and Secret Hash do not match, update existing")
					err := createSecret(ctx, client, log, Namespace.Name, secretNameWithHash)
					if err != nil {
						log.Error(fmt.Errorf(err.Error()), "failed to update secret")
						break
					}
				}

			} else {

				err = createSecret(ctx, client, log, Namespace.Name, secretNameWithHash)
				if err != nil {
					log.Error(fmt.Errorf(err.Error()), "failed to create secret")
					break
				}
			}

		case <-channel:
			log.Info("Channel is closing and ticker stopped")
			ticker.Stop()
			return fmt.Errorf("channel closed")
		}
	}
}

func createNameSpaceIfNotPresent(ctx context.Context, log logr.Logger, client client.Client, namespace string) (*v1.Namespace, error) {
	var Namespace v1.Namespace

	err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: namespace}, &Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("namespace: %s not present, creating", namespace)
			Namespace := v1.Namespace{
				ObjectMeta: v12.ObjectMeta{
					Name:      namespace,
					Namespace: namespace,
				},
			}
			client.Create(ctx, &Namespace)
		} else {
			return nil, fmt.Errorf("error getting namespace: %s/%s", Namespace.Name, err.Error())
		}
	}

	return &Namespace, nil
}

func checkIfSecretPresent(ctx context.Context, client client.Client, log logr.Logger, namespace string, secretName string) (*v1.Secret, bool, error) {
	var secret v1.Secret

	err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret)
	if errors.IsNotFound(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("error getting secret: %s/%s", secretName, err.Error())
	} else {
		return &secret, true, nil
	}
}

// func createNewSecretVersion(ctx context.Context, client client.Client, log logr.Logger, namespace string, secretName string) error {
// 	log.Info("Create a new secret version")

// 	var secret v1.Secret
// 	err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret)
// 	if err != nil {
// 		return fmt.Errorf("error getting secret: %s/%s", secretName, err.Error())
// 	} else {
// 		createSecret := createSecret(ctx, client, log, namespace, secretName)
// 		if createSecret != nil {
// 			return fmt.Errorf("failed to create secret while trying to update: %s/%s", secretName, err.Error())
// 		}

// 	}
// 	return err
// }

func createSecret(ctx context.Context, client client.Client, log logr.Logger, namespace string, secretName string) error {

	log.Info("Creating New Secret")
	var secret v1.Secret

	if err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret); err != nil {
		if errors.IsNotFound(err) {
			secret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   namespace,
					Name:        secretName,
					Annotations: map[string]string{},
					Labels:      map[string]string{},
				},
				Data: map[string][]byte{},
			}
		} else if err != nil {
			return fmt.Errorf("failed to get destination secret: %s", err.Error())
		}
	}

	clusterCert, err := getCert(log)
	if err != nil {
		return fmt.Errorf("failed to get cluster ca: %s", err.Error())
	}

	certBytes := make([]byte, 0)
	certBytes = append(certBytes, clusterCert.content...)

	hash, err := certHasher(certBytes)
	if err != nil {
		return fmt.Errorf("failed to hash of secret certificate during creation: %s", err.Error())
	}

	secret.Annotations[CurrentCertificateHashAnnotation] = hex.EncodeToString((hash))
	secret.Annotations[TrustedCertificateAnnotation] = "true"

	secret.Labels["trustbuilder-global"] = "cluster-ca"
	secret.Data[secretName] = certBytes
	return client.Create(ctx, &secret)
}

func getCert(log logr.Logger) (*PemCertificate, error) {

	pc, err := getClusterCAPemCertificate(log)

	if err != nil {
		return &PemCertificate{}, fmt.Errorf("failed to get cluster ca certificate: %s", err.Error())
	} else if pc != nil {
		log.Info("The Cluster CA file is present")
	}
	return pc, nil
}

func getPemCertificateHash(cert PemCertificate, log logr.Logger) (string, error) {

	certBytes := make([]byte, 0)
	certBytes = append(certBytes, cert.content...)

	// log.Info(fmt.Sprintf("hashing certificate byte array with length: %d", len(certBytes)))

	if hash, err := certHasher(certBytes); err != nil {
		return "", fmt.Errorf("failed to hash certificate: %s", err.Error())
	} else {
		return hex.EncodeToString(hash), nil
	}
}
