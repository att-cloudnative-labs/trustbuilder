package controllers

import (
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func ClusterCaToSecretExample() {
	log := log.Log.WithName("ClusterCAToSecret")

	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:
			cert, err := getCertExample(log)
			if err != nil {
				log.Error(err, "Error getting cert")
			} else {
				log.Info("Cert Present")
				log.Info(cert.alias)

			}
		case <-quit:
			ticker.Stop()
			return
		}
	}
}

func getCertExample(log logr.Logger) (*PemCertificate, error) {

	pc, err := getClusterCAPemCertificate(log)

	if err != nil {
		return &PemCertificate{}, fmt.Errorf("failed to get cluster ca certificate: %s", err.Error())
	} else if pc != nil {
		log.Info("cluster CA file present")
	}

	return pc, nil
}
