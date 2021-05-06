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
	empty_policy = "/test_files/empty_policy.json"
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
