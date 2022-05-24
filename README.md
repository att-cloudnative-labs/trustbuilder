# Trustbuilder

---

<p align="center">
  <a href="https://goreportcard.com/report/github.com/att-cloudnative-labs/trustbuilder" alt="Go Report Card">
    <img src="https://goreportcard.com/badge/github.com/att-cloudnative-labs/trustbuilder">
  </a>
</p>
<p align="center">
    <a href="https://github.com/att-cloudnative-labs/trustbuilder/graphs/contributors" alt="Contributors">
		<img src="https://img.shields.io/github/contributors/att-cloudnative-labs/trustbuilder.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/commits/master" alt="Commits">
		<img src="https://img.shields.io/github/commit-activity/m/att-cloudnative-labs/trustbuilder.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/pulls" alt="Open pull requests">
		<img src="https://img.shields.io/github/issues-pr-raw/att-cloudnative-labs/trustbuilder.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/pulls" alt="Closed pull requests">
    	<img src="https://img.shields.io/github/issues-pr-closed-raw/att-cloudnative-labs/trustbuilder.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/issues" alt="Issues">
		<img src="https://img.shields.io/github/issues-raw/att-cloudnative-labs/trustbuilder.svg">
	</a>
	</p>
<p align="center">
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/stargazers" alt="Stars">
		<img src="https://img.shields.io/github/stars/att-cloudnative-labs/trustbuilder.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/watchers" alt="Watchers">
		<img src="https://img.shields.io/github/watchers/att-cloudnative-labs/trustbuilder.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/trustbuilder/network/members" alt="Forks">
		<img src="https://img.shields.io/github/forks/att-cloudnative-labs/trustbuilder.svg?style=social">
	</a>
</p>

----

Trustbuilder is custom-controller and custom-resource that allows for automatic creation of stores for trusted certificates which include PEM files and Java Keystore (JKS) files. The custom resource CertificatePackage defines an output certificate store and a selector that identifies which secrets/configmaps contain certificates that should be added to the indicated certificate store.

----
### CertificatePackage Resource Spec
```yaml
resourceType: "output resource type (secret/configmap) - required"
resourceName: "output resource name - required"
key: "key within the output resource data to place the certificate store - required"
passwordSecret: "secret containing the password to sign JKS keystore with - required only for JKS type only"
passwordSecretKey: "key within the passwordSecret containing the password data - required only for JKS type only"
addClusterCA: "(true/false) include the cluster CA in the certificate store. Default: false"
selector: "label selector that selects which secrets contain the source trusted certificates"
```

### Source Trusted Certificates

Secrets and configMaps to be used as sources of trusted certificates should have the annotation ```trustbuilder.directv.com/trustedcertificate: "true"``` in addition to a common set of labels that match the selector in the CertificatePackage object.

----
### Installation

```shell script
make install
make deploy IMG=<trustbuilder-image-tag>
```

----

*Developed using the Kubebuilder Framework, https://github.com/kubernetes-sigs/kubebuilder
