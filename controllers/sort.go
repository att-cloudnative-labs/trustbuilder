package controllers

import v1 "k8s.io/api/core/v1"

type ConfigMapByName []v1.ConfigMap
type SecretByName []v1.Secret

func (s ConfigMapByName) Len() int {
	return len(s)
}
func (s ConfigMapByName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ConfigMapByName) Less(i, j int) bool {
	return s[i].Name < s[j].Name
}
