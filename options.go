package ldproofs

import "errors"

type signatureOptions struct {
	purpose Purpose
	suite   SignatureSuite
}

type SignatureOption func(*signatureOptions)

func WithPurpose(purpose Purpose) SignatureOption {
	return func(o *signatureOptions) {
		o.purpose = purpose
	}
}

func WithSignatureSuite(suite SignatureSuite) SignatureOption {
	return func(o *signatureOptions) {
		o.suite = suite
	}
}

func resolveOptions(options ...SignatureOption) (*signatureOptions, error) {
	theOptions := signatureOptions{
		// default purpose value
		purpose: AssertionMethod,
	}
	for _, opt := range options {
		opt(&theOptions)
	}
	if theOptions.suite == nil {
		return nil, errors.New("missing_signature_suite")
	}
	return &theOptions, nil
}
