package ldproofs_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gossif/ldproofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalization(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful normalization": testNormalizationt,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testNormalizationt(t *testing.T) {

	doc := `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
			{
				"@vocab": "https://example.com/#"
			}
		],
		"type": [
			"VerifiableCredential"
		],
		"issuer": "did:example:123",
		"issuanceDate": "2022-03-19T15:20:55Z",
		"credentialSubject": {
			"foo": "bar"
		},
		"proof": {
			"type": "JsonWebSignature2020",
			"created": "2022-08-10T18:51:08Z",
			"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9..pbMMGpP0cQ9N2UZ47ke5VTlaiUim2dsIzVj5wNSvNSrsN-hSf6-WOeDYhasRqrkqsLc1VAuOkIlaUgNXiAJhAA",
			"proofPurpose": "assertionMethod",
			"verificationMethod": "did:example:123#key-0"
		}
	}`
	var v map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(doc), &v))

	proof := v["proof"].(map[string]interface{})
	delete(v, "proof")
	delete(proof, "jws")
	proof["@context"] = v["@context"]

	docCanocalized, _ := ldproofs.NormalizeTriples(v)
	proofCanocalized, _ := ldproofs.NormalizeTriples(proof)

	docDigest := hashSha256(docCanocalized)
	proofOptionsDigest := hashSha256(proofCanocalized)

	assert.Equal(t, "954ec772d3d4c62f25dbef561c0ee0083f2623c0ffd6191a27588f8e977c375d", hex.EncodeToString(docDigest))
	assert.Equal(t, "3b8fdf8fdeb25b1b44d021e2d412e11c85252f588434c10a199d2c6e5d327f45", hex.EncodeToString(proofOptionsDigest))

}

func hashSha256(input string) []byte {
	sum := sha256.Sum256([]byte(input))
	return sum[:]
}
