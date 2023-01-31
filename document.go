package ldproofs

import (
	"encoding/json"
)

type DocumentLoader interface {
	GetDocument() Document
	AddLinkedDataProof(options ...SignatureOption) error
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

func (d *jsonldDocument) VerifyLinkedDataProof(options ...SignatureOption) error {
	theOptions, err := resolveOptions(options...)
	if err != nil {
		return err
	}
	return theOptions.suite.VerifyLinkedDataProof(d, options...)
}
