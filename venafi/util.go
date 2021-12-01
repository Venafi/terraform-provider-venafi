package venafi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/pkg/errors"
	"log"
	"math/rand"
	"strconv"
	"strings"
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
		/* #nosec */
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

//nolint
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
	key_algo             string
	expiration_window    int
	custom_fields        string
	issuer_hint          string
	valid_days           int
	zone                 string
	filePath             string
	keyId                string
	template             string
	publicKeyMethod      string
	sourceAddress        string
	validityPeriod       string
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

func getIssuerHint(is string) string {

	issuerHint := ""

	if is != "" {

		issuerOpt := string(is[0])
		issuerOpt = strings.ToLower(issuerOpt)

		switch issuerOpt {

		case "m":
			issuerHint = util.IssuerHintMicrosoft
		case "d":
			issuerHint = util.IssuerHintDigicert
		case "e":
			issuerHint = util.IssuerHintEntrust
		}

	}

	return issuerHint

}

func getConnection(meta interface{}) (endpoint.Connector, error) {
	cfg := meta.(*vcert.Config)
	cl, err := vcert.NewClient(cfg)
	if err != nil {
		log.Printf(messageVenafiClientInitFailed + err.Error())
		return nil, err
	}
	err = cl.Ping()
	if err != nil {
		log.Printf(messageVenafiPingFailed + err.Error())
		return nil, err
	}
	log.Println(messageVenafiPingSucessfull)

	return cl, nil
}

func buildSshCertRequest(d *schema.ResourceData) certificate.SshCertRequest {

	req := certificate.SshCertRequest{}
	id := d.Get("key_id").(string)
	req.KeyId = id

	template := d.Get("template").(string)
	req.Template = template

	if keyPassphrase, ok := d.Get("key_passphrase").(string); ok {
		req.PrivateKeyPassphrase = keyPassphrase
	}
	if folder, ok := d.Get("folder").(string); ok {
		req.PolicyDN = folder
	}
	if forceCommand, ok := d.Get("force_command").(string); ok {
		req.ForceCommand = forceCommand
	}
	if validHours, ok := d.Get("valid_hours").(int); ok {
		if validHours > 0 {
			req.ValidityPeriod = strconv.Itoa(validHours) + "h"
		}
	}
	if objectName, ok := d.Get("object_name").(string); ok {
		req.ObjectName = objectName
	}
	if principal, ok := d.GetOk("principal"); ok {
		req.Principals = getStringList(principal)
	}
	if sourceAddress, ok := d.GetOk("source_address"); ok {
		req.SourceAddresses = getStringList(sourceAddress)
	}
	if destinationAddress, ok := d.GetOk("destination_address"); ok {
		req.DestinationAddresses = getStringList(destinationAddress)
	}
	if extension, ok := d.GetOk("extension"); ok {
		req.Extensions = getStringList(extension)
	}

	return req
}

func getStringList(i interface{}) []string {

	arr := i.([]interface{})

	if len(arr) == 0 {
		return nil
	}

	strs := make([]string, 0, len(arr))

	for _, val := range arr {
		strs = append(strs, val.(string))
	}

	return strs
}

func validateSshCertValues(d *schema.ResourceData) error {
	id := d.Get("key_id").(string)
	if id == "" {
		return fmt.Errorf("key_id is empty")
	}

	if template := d.Get("template").(string); template == "" {
		return fmt.Errorf("template is empty")
	}

	kpMethod := d.Get("public_key_method").(string)

	if kpMethod == "file" {
		public_key := d.Get("public_key").(string)
		if public_key == "" {
			return fmt.Errorf("file public key method is specified but public_key is empty")
		}
	}

	return nil
}
