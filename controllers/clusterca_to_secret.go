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

func ClusterCaToSecret(client client.Client) {
	log := log.Log.WithName("ClusterCAToSecret")
	// var api interface {
	// 	client.Client
	// }
	log.Info("Starting Ticker")

	ticker := time.NewTicker(20 * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:

			isPresent, err := checkIfSecretPresent(context.Background(), client, log)

			if isPresent {
				// check the hash of the secret data with cert.
				sec, err := getSecret(context.Background(), client, log)
				if err != nil {
					log.Error(err, "failed to get secret")
				}

				clusterCert, err := getCert(log)
				if err != nil {
					log.Error(err, "failed to get cluster CA")
				}

				clusterCAPemCertHash, err := getPemCertificateHash(*clusterCert, log)
				if err != nil {
					log.Error(err, "failed to get cluster CA Hash")
				}

				if clusterCAPemCertHash == getCertificateHashFromSecret(*sec) {
					log.Info("Cert and Secret Hash Match, do nothing...")
				} else {
					log.Info("Cert and Secret Hash do not match, update existing")
					updateSecret(context.Background(), client, log)
				}

			} else {

				if err != nil {
					log.Error(err, "Secret Not Found")
				}

				err := createSecret(context.Background(), client, log)
				if err != nil {
					log.Error(err, "Error creating secret")
				}

			}

		case <-quit:
			ticker.Stop()
			return
		}
	}
}

func getSecret(ctx context.Context, client client.Client, log logr.Logger) (*v1.Secret, error) {
	var secret v1.Secret

	err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-ca-secret"}, &secret)

	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %s", err.Error())
	}

	return &secret, nil
}

func checkIfSecretPresent(ctx context.Context, client client.Client, log logr.Logger) (bool, error) {
	var secret v1.Secret

	err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-ca-secret"}, &secret)

	if err != nil {
		log.Error(err, "Error while checking for secret")
	} else {
		return true, err
	}
	return false, err
}

func updateSecret(ctx context.Context, client client.Client, log logr.Logger) {
	log.Info("Update Secret Function")

	var secret v1.Secret
	sec := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-ca-secret"}, &secret)
	if sec != nil {
		log.Error(sec, "Error while checking for secret")
	} else {
		err := client.Delete(ctx, &secret)

		if err != nil {
			log.Error(err, "Unable to delete secret")
		}

		createSecret := createSecret(ctx, client, log)
		if createSecret != nil {
			log.Error(createSecret, "Error creating secret")
		}

	}
}

func createSecret(ctx context.Context, client client.Client, log logr.Logger) error {

	fmt.Println("Creating New Secret")
	var secret v1.Secret

	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-ca-secret"}, &secret); err != nil {
		if errors.IsNotFound(err) {
			secret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   "default",
					Name:        "cluster-ca-secret",
					Annotations: map[string]string{},
				},
				Data: map[string][]byte{},
			}
		} else if err != nil {
			return fmt.Errorf("failed to get destination secret: %s", err.Error())
		}
	}

	clusterCert, err := getCert(log)
	if err != nil {
		log.Error(err, "failed to get cluster CA")
	}

	certBytes := make([]byte, 0)
	certBytes = append(certBytes, clusterCert.content...)

	hash, err := certHasher(certBytes)
	if err != nil {
		return fmt.Errorf("failed to hash of secret certificate: %s", err.Error())
	}

	secret.Annotations[CurrentCertificateHashAnnotation] = hex.EncodeToString((hash))

	// secret.Data = map[string][]byte{}
	secret.Data["cluster-ca-secret"] = certBytes
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

	log.V(2).Info(fmt.Sprintf("hashing certificate byte array with length: %d", len(certBytes)))
	// // we add the password secret and key so that changes to that update the has
	// certBytes = append(certBytes, []byte(cp.Spec.PasswordSecret)...)
	// certBytes = append(certBytes, []byte(cp.Spec.PasswordSecretKey)...)
	if hash, err := certHasher(certBytes); err != nil {
		return "", fmt.Errorf("failed to hash certificate: %s", err.Error())
	} else {
		return hex.EncodeToString(hash), nil
	}
}
