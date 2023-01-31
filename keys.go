package ldproofs

import (
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type KeyAlgorithm struct {
	kty jwa.KeyType
	crv jwa.EllipticCurveAlgorithm
	alg jwa.SignatureAlgorithm
	key interface{}
}

func NewAlgorithm(jwkKey jwk.Key) (*KeyAlgorithm, error) {
	var (
		err error
		k   KeyAlgorithm
	)
	var ellipticCurve jwa.EllipticCurveAlgorithm
	if curve, ok := jwkKey.Get("crv"); ok {
		ellipticCurve = curve.(jwa.EllipticCurveAlgorithm)
	}
	k = KeyAlgorithm{kty: jwkKey.KeyType(), crv: ellipticCurve}
	k.alg, err = k.getAlgorithm()
	if err != nil {
		return nil, err
	}
	err = jwkKey.Raw(&k.key)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (k *KeyAlgorithm) getAlgorithm() (jwa.SignatureAlgorithm, error) {
	switch k.kty {
	case jwa.EC:
		switch k.crv {
		case jwa.P384:
			return jwa.ES384, nil
		case "secp256k1":
			return jwa.ES256K, nil
		case jwa.P256:
			return jwa.ES256, nil
		default:
			return "", errors.New("unsupported_curve")
		}
	case jwa.OKP:
		return jwa.EdDSA, nil
	case jwa.RSA:
		return jwa.PS256, nil
	default:
		return "", errors.New("unsupported_algorithm")
	}
}

func (k *KeyAlgorithm) Sign(message []byte) ([]byte, error) {
	signer, err := jws.NewSigner(k.alg)
	if err != nil {
		return nil, err
	}
	return signer.Sign(message, k.key)
}

func (k *KeyAlgorithm) Verify(message []byte, signature []byte) error {
	verifier, err := jws.NewVerifier(k.alg)
	if err != nil {
		return err
	}
	return verifier.Verify(message, signature, k.key)
}
