package controllers

import (
	"crypto"
	"fmt"
	"reflect"
)

func certHasher(objs ...interface{}) ([]byte, error) {
	digester := crypto.MD5.New()
	for _, ob := range objs {
		if _, err := fmt.Fprint(digester, reflect.TypeOf(ob)); err != nil {
			return nil, fmt.Errorf("failed to hash certificate object: %s", err.Error())
		}
		if _, err := fmt.Fprint(digester, ob); err != nil {
			return nil, fmt.Errorf("failed to hash certificate object: %s", err.Error())
		}
	}
	return digester.Sum(nil), nil
}
