package venafi

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func sliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func encodePKCS1PrivateRSAKey(pk *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}

	return pem.EncodeToMemory(block)
}

func encodePKCS1PrivateECDSAKey(pk *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		log.Println("Can't marsha EC key: ", err)
		return nil
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.EncodeToMemory(block)
}

func getPrivateKeyPEMBock(key interface{}) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("Unable to format Key")
	}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func readPublicKey(rsaKey interface{}) (string, error) {
	pubKey := publicKey(rsaKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "failed to marshal public key error", err
	}
	pubKeyPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	return string(pem.EncodeToMemory(pubKeyPemBlock)), nil
}
