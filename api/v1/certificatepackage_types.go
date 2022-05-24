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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CertificatePackageSpec defines the desired state of CertificatePackage
type CertificatePackageSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// PackageType package type (jks, pem)
	PackageType string `json:"packageType,omitempty"`
	// ResourceType resource type (secret, configmap)
	ResourceType      string               `json:"resourceType,omitempty"`
	ResourceName      string               `json:"resourceName,omitempty"`
	Key               string               `json:"key,omitempty"`
	Selector          metav1.LabelSelector `json:"selector,omitempty"`
	AddClusterCA      string               `json:"addClusterCA,omitempty"`
	PasswordSecret    string               `json:"passwordSecret,omitempty"`
	PasswordSecretKey string               `json:"passwordSecretKey,omitempty"`
}

// CertificatePackageStatus defines the observed state of CertificatePackage
type CertificatePackageStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CertificatePackage is the Schema for the certificatepackages API
type CertificatePackage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificatePackageSpec   `json:"spec,omitempty"`
	Status CertificatePackageStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificatePackageList contains a list of CertificatePackage
type CertificatePackageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificatePackage `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificatePackage{}, &CertificatePackageList{})
}
