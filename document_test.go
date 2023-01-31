package ldproofs_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gossif/ldproofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJws2020Signing(t *testing.T) {
	// Find the paths of all credential files in the data directory.
	allCredentials, err := filepath.Glob(filepath.Join("testdata/credentials", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Find the paths of all key files in the data directory.
	allKeys, err := filepath.Glob(filepath.Join("testdata/keys", "*.json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, credential := range allCredentials {
		_, filename := filepath.Split(credential)
		scenarioStep1 := filename[:len(filename)-len(filepath.Ext(credential))]
		scenarioStep2 := strings.Split(scenarioStep1, "--")

		jsonCredential, err := os.ReadFile(credential)
		if err != nil {
			t.Fatal("error reading credential file:", err)
		}

		for _, key := range allKeys {
			_, filename := filepath.Split(key)
			scenarioStep3 := filename[:len(filename)-len(filepath.Ext(key))]
			scenarioStep4 := strings.Split(scenarioStep3, "-")

			scenarioDescription := fmt.Sprintf("%s with %s", scenarioStep2[0], scenarioStep4[2])

			jsonKey, err := os.ReadFile(key)
			if err != nil {
				t.Fatal("error reading key file:", err)
			}

			t.Run(scenarioDescription, func(t *testing.T) {

				doc, err := ldproofs.NewDocument(jsonCredential)
				require.NoError(t, err)

				suite := ldproofs.NewJSONWebSignature2020Suite()
				suite.ParseSignatureKey(jsonKey)

				assert.NoError(t, doc.AddLinkedDataProof(ldproofs.WithSignatureSuite(suite), ldproofs.WithPurpose(ldproofs.AssertionMethod)))
			})
		}
	}
}

func TestJws2020Verification(t *testing.T) {

	// Find the paths of all key files in the data directory.
	allKeys, err := filepath.Glob(filepath.Join("testdata/keys", "*.json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range allKeys {
		_, filename := filepath.Split(key)
		scenarioStep1 := filename[:len(filename)-len(filepath.Ext(key))]
		scenarioStep2 := strings.Split(scenarioStep1, "-")

		jsonKey, err := os.ReadFile(key)
		if err != nil {
			t.Fatal("error reading key file:", err)
		}
		// Find the paths of all credential files in the data directory.
		allCredentials, err := filepath.Glob(filepath.Join("testdata/implementation/transmute", fmt.Sprintf("*%s.vc.json", scenarioStep2[2])))
		if err != nil {
			t.Fatal(err)
		}

		for _, credential := range allCredentials {
			_, filename := filepath.Split(credential)
			scenarioStep3 := filename[:len(filename)-len(filepath.Ext(credential))]
			scenarioStep4 := strings.Split(scenarioStep3, "--")
			scenarioDescription := fmt.Sprintf("%s with %s", scenarioStep2[2], scenarioStep4[0])

			jsonCredential, err := os.ReadFile(credential)
			if err != nil {
				t.Fatal("error reading credential file:", err)
			}

			t.Run(scenarioDescription, func(t *testing.T) {

				doc, err := ldproofs.NewDocument(jsonCredential)
				require.NoError(t, err)

				suite := ldproofs.NewJSONWebSignature2020Suite()
				suite.ParseVerificationKey(jsonKey)

				assert.NoError(t, doc.VerifyLinkedDataProof(ldproofs.WithSignatureSuite(suite)))
			})
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"signing and verifying": testSignDocument,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSignDocument(t *testing.T) {
	rawdoc := `{
		"@context": [
		  "https://www.w3.org/2018/credentials/v1",
		  "https://w3id.org/security/suites/jws-2020/v1",
		  { "@vocab": "https://example.com/#" }
		],
		"type": ["VerifiableCredential"],
		"issuer": "did:example:123",
		"issuanceDate": "2022-03-19T15:20:55Z",
		"credentialSubject": {
		  "foo": "bar"
		}
	  }`

	rawkey := `{
		"id": "did:example:123#key-0",
		"type": "JsonWebKey2020",
		"controller": "did:example:123",
		"publicKeyJwk": {
		  "kty": "OKP",
		  "crv": "Ed25519",
		  "x": "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is"
		},
		"privateKeyJwk": {
		  "kty": "OKP",
		  "crv": "Ed25519",
		  "x": "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		  "d": "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE"
		}
	  }`

	doc, err := ldproofs.NewDocument([]byte(rawdoc))
	require.NoError(t, err)

	suite := ldproofs.NewJSONWebSignature2020Suite()
	suite.ParseSignatureKey([]byte(rawkey))

	assert.NoError(t, doc.AddLinkedDataProof(ldproofs.WithSignatureSuite(suite), ldproofs.WithPurpose(ldproofs.AssertionMethod)))

	bytes, _ := json.MarshalIndent(doc.GetDocument(), "", "    ")
	fmt.Println(string(bytes))
	suite.ParseVerificationKey([]byte(rawkey))
	assert.NoError(t, doc.VerifyLinkedDataProof(ldproofs.WithSignatureSuite(suite)))
}
