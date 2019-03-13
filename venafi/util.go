package venafi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"math/rand"
	"time"
)

func sliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func randSeq(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}

type testData struct {
	cert                 string
	private_key          string
	private_key_password string
	wrong_cert           string
	wrong_pkey           string
	cn                   string
	dns_ns               string
	dns_ip               string
	dns_email            string
	provider             string
	serial               string
	timeCheck            string
	key_algo			 string
	expiration_window	 int
}

func getPrivateKey(keyBytes []byte, passphrase string) ([]byte, error) {
	// this section makes some small changes to code from notary/tuf/utils/x509.go
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("no valid private key found")
	}

	var err error
	if x509.IsEncryptedPEMBlock(pemBlock) {
		keyBytes, err = x509.DecryptPEMBlock(pemBlock, []byte(passphrase))
		if err != nil {
			return nil, errors.Wrap(err, "private key is encrypted, but could not decrypt it")
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: pemBlock.Type, Bytes: keyBytes})
	}

	return keyBytes, nil
}
