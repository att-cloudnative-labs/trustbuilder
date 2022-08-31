package controllers

import (
	"context"
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

func ClusterCaToSecret(ctx context.Context) {
	log := log.Log.WithName("ClusterCAToSecret")

	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:
			cert, err := getCert(log)
			if err != nil {
				log.Error(err, "Error getting cert")
			} else {

				fmt.Println(cert)
				fmt.Println(createSecIfNotPresent(ctx))
				// check if secret exists

			}
		case <-quit:
			ticker.Stop()
			return
		}
	}
}

func createSecIfNotPresent(ctx context.Context) (*v1.Secret, error) {

	var secret v1.Secret
	var api interface {
		client.Client
	}

	if err := api.Get(ctx, types.NamespacedName{Namespace: "global-trust-certificates", Name: "cluster-ca-secret"}, &secret); err != nil {
		if errors.IsNotFound(err) {
			secret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   "global-trust-certificates",
					Name:        "cluster-ca-secret",
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

func getCert(log logr.Logger) (*PemCertificate, error) {

	pc, err := getClusterCAPemCertificate(log)

	if err != nil {
		return &PemCertificate{}, fmt.Errorf("failed to get cluster ca certificate: %s", err.Error())
	} else if pc != nil {
		log.Info("cluster CA file present")
	}

	return pc, nil
}
