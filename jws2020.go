package ldproofs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type jws2020Suite struct {
	keyPair JWKKeyPair
}

type JWKKeyPair struct {
	Id           string          `json:"id,omitempty"`
	Type         string          `json:"type,omitempty"`
	Controller   string          `json:"controller,omitempty"`
	PubicKey     json.RawMessage `json:"publicKeyJwk,omitempty"`
	PrivateKey   json.RawMessage `json:"privateKeyJwk,omitempty"`
	keyAlgorithm *KeyAlgorithm   `json:"-"`
}

func NewJSONWebSignature2020Suite() SignatureSuite {
	return &jws2020Suite{}
}

func (k *jws2020Suite) ParseSignatureKey(privateKey []byte) error {
	kp := JWKKeyPair{}
	if privateKey == nil {
		return errors.New("missing_key")
	}
	err := json.Unmarshal(privateKey, &kp)
	if err != nil {
		return err
	}
	var jwkKey jwk.Key
	if kp.PrivateKey != nil {
		jwkKey, err = jwk.ParseKey(kp.PrivateKey)
		if err != nil {
			return err
		}
	} else {
		return errors.New("missing_private_key")
	}
	keyAlgorithm, err := NewAlgorithm(jwkKey)
	if err != nil {
		return err
	}
	kp.keyAlgorithm = keyAlgorithm
	k.keyPair = kp
	return nil
}

func (k *jws2020Suite) ParseVerificationKey(publicKey []byte) error {
	kp := JWKKeyPair{}
	if publicKey == nil {
		return errors.New("missing_key")
	}
	err := json.Unmarshal(publicKey, &kp)
	if err != nil {
		return err
	}
	var jwkKey jwk.Key
	if kp.PubicKey != nil {
		jwkKey, err = jwk.ParseKey(kp.PubicKey)
		if err != nil {
			return err
		}
	} else {
		return errors.New("missing_public_key")
	}
	keyAlgorithm, err := NewAlgorithm(jwkKey)
	if err != nil {
		return err
	}
	kp.keyAlgorithm = keyAlgorithm
	k.keyPair = kp
	return nil
}

func (k *jws2020Suite) GetKeyType() string {
	return "JsonWebKey2020"
}

func (k *jws2020Suite) GetSignatureType() string {
	return "JsonWebSignature2020"
}

func (k *jws2020Suite) AddLinkedDataProof(document DocumentLoader, options ...SignatureOption) error {
	doc, proofOptions, err := k.prepareMessage(document, options...)
	if err != nil {
		return err
	}
	// compose the jws header
	header := map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
	headerBytes, _ := json.Marshal(header)
	jwtHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	message := composeMessage(jwtHeader, doc, proofOptions)
	// sign the message with the key algorithm
	signed, err := k.keyPair.keyAlgorithm.Sign(message)
	if err != nil {
		return err
	}
	proofOptions["jws"] = jwtHeader + ".." + base64.RawURLEncoding.EncodeToString(signed)
	delete(proofOptions, "@context")
	doc["proof"] = proofOptions
	return nil
}

// prepareMessage prepares the document and proof options for signing
func (k *jws2020Suite) prepareMessage(document DocumentLoader, options ...SignatureOption) (Document, Proof, error) {
	theOptions, err := resolveOptions(options...)
	if err != nil {
		return nil, nil, err
	}
	// prepare the document and the proof options
	doc := document.GetDocument()
	proofOptions := Proof{
		"type":               k.GetSignatureType(),
		"created":            time.Now().UTC().Format(time.RFC3339),
		"verificationMethod": k.keyPair.Id,
		"proofPurpose":       theOptions.purpose.String(),
	}
	var context []interface{}
	switch ctx := doc["@context"].(type) {
	case []interface{}:
		context = ctx
	case interface{}:
		context = append(context, ctx)
	}
	contextBytes, err := json.Marshal(context)
	if err != nil {
		return nil, nil, err
	}
	// check if the context contains the security context, add if missing
	if !strings.Contains(string(contextBytes), "https://w3id.org/security/suites/jws-2020/v1") {
		context = append(context, "https://w3id.org/security/suites/jws-2020/v1")
	}
	doc["@context"] = context
	proofOptions["@context"] = doc["@context"]

	return doc, proofOptions, nil
}

func composeMessage(jwtHeader string, doc Document, proofOptions Proof) []byte {
	// normalize (canonicalize) the document and the proof options
	docCanocalized, _ := NormalizeTriples(doc)
	proofOptionsCanocalized, _ := NormalizeTriples(proofOptions)
	// calculate the hash sum of the document and the proof options
	docDigest := hashSha256(docCanocalized)
	proofOptionsDigest := hashSha256(proofOptionsCanocalized)
	// concat the digest values
	verifyData := append(proofOptionsDigest, docDigest...)
	// add the protected header to the payload with an extra dot
	message := append([]byte(jwtHeader+"."), verifyData...)
	return message
}

func (k *jws2020Suite) VerifyLinkedDataProof(document DocumentLoader, options ...SignatureOption) error {
	doc := document.GetDocument()

	var proofOptions Proof
	switch proof := doc["proof"].(type) {
	case map[string]interface{}:
		// when the document is loaded as a new document
		proofOptions = Proof(proof)
	case Proof:
		// when the document has just been signed
		proofOptions = proof
	default:
		return errors.New("missing_proof")
	}
	delete(doc, "proof")
	jws, jwsOk := proofOptions["jws"].(string)
	if jwsOk {
		delete(proofOptions, "jws")
	}
	proofOptions["@context"] = doc["@context"]

	jwtHeader, jwtSignature, err := splitJSONWebToken(jws)
	if err != nil {
		return err
	}
	message := composeMessage(jwtHeader, doc, proofOptions)
	signature, _ := base64.RawURLEncoding.DecodeString(jwtSignature)
	// verify the message with the key algorithm
	err = k.keyPair.keyAlgorithm.Verify(message, signature)
	if err != nil {
		return err
	}
	return nil
}

func splitJSONWebToken(token string) (string, string, error) {
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return "", "", errors.New("invalid_jsonwebtoken")
	}
	return jwtParts[0], jwtParts[2], nil
}

func hashSha256(input string) []byte {
	sum := sha256.Sum256([]byte(input))
	return sum[:]
}
