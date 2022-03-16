package venafi

import (
	"fmt"
	"math/rand"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

const (
	emptyPolicy       = "/test_files/empty_policy.json"
	policySpecVaas    = "/test_files/policy_specification_vaas.json"
	policySpecTpp     = "/test_files/policy_specification_tpp.json"
	policyReadSpecTpp = "/test_files/policy_specification_tpp_management.json"
)

func RandAppName() string {
	return fmt.Sprintf("terraform-provider-%d-%sAppOpenSource", time.Now().Unix(), randRunes(4))
}

func RandCitName() string {
	return fmt.Sprintf("t%d-%sCitOpenSource", time.Now().Unix(), randRunes(4))
}

func RandTppPolicyName() string {
	return fmt.Sprintf("terraform-provider-%d-%sPolicyOpenSource", time.Now().Unix(), randRunes(4))
}

func randRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GetRootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func IsArrayStringEqual(expectedValues, values []string) bool {

	if len(expectedValues) != len(values) {
		return false
	}

	for i, currentValue := range expectedValues {

		if currentValue != values[i] {

			return false

		}

	}

	return true
}

func GetAbsoluteFIlePath(filePath string) string {
	rootDir := GetRootDir()
	absolutePath := rootDir + filePath
	return absolutePath
}

func RandTppSshCertName() string {
	return fmt.Sprintf("terraform-provider-%d-%sSSH-cert", time.Now().Unix(), randRunes(4))
}
