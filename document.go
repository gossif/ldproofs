package ldproofs

import (
	"encoding/json"
	"errors"
)

type DocumentLoader interface {
	GetDocument() Document
	AddLinkedDataProof(options ...SignatureOption) error
	GetLinkedDataProofType() (string, error)
	VerifyLinkedDataProof(options ...SignatureOption) error
}

type Document map[string]interface{}

type jsonldDocument struct {
	doc Document
}

func NewDocument(doc []byte) (DocumentLoader, error) {
	var v map[string]interface{}
	err := json.Unmarshal(doc, &v)
	if err != nil {
		return nil, err
	}
	return &jsonldDocument{
		doc: v,
	}, nil
}

func (d *jsonldDocument) GetDocument() Document {
	return d.doc
}

func (d *jsonldDocument) AddLinkedDataProof(options ...SignatureOption) error {
	theOptions, err := resolveOptions(options...)
	if err != nil {
		return err
	}
	return theOptions.suite.AddLinkedDataProof(d, options...)
}

func (d *jsonldDocument) GetLinkedDataProofType() (string, error) {
	var proofOptions Proof
	switch proof := d.doc["proof"].(type) {
	case map[string]interface{}:
		// when the document is loaded as a new document
		proofOptions = Proof(proof)
	case Proof:
		// when the document has just been signed
		proofOptions = proof
	default:
		return "", errors.New("missing_proof")
	}
	ldproofType, ok := proofOptions["type"].(string)
	if !ok {
		return "", errors.New("missing_linked_data_proof_type")
	}
	return ldproofType, nil
}

func (d *jsonldDocument) VerifyLinkedDataProof(options ...SignatureOption) error {
	theOptions, err := resolveOptions(options...)
	if err != nil {
		return err
	}
	return theOptions.suite.VerifyLinkedDataProof(d, options...)
}
