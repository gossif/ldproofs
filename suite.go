package ldproofs

type SignatureSuite interface {
	ParseSignatureKey(privateKey []byte) error
	ParseVerificationKey(publicKey []byte) error
	GetKeyType() string
	GetSignatureType() string
	AddLinkedDataProof(document DocumentLoader, options ...SignatureOption) error
	VerifyLinkedDataProof(document DocumentLoader, options ...SignatureOption) error
}
