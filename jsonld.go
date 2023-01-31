package ldproofs

import (
	"errors"
	"net/http"
	"strings"

	"github.com/piprate/json-gold/ld"
)

func NormalizeTriples(doc map[string]interface{}) (string, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.ProduceGeneralizedRdf = true
	options.DocumentLoader = ld.NewDefaultDocumentLoader(http.DefaultClient)

	normalizedTriples, err := proc.Normalize(doc, options)
	if err != nil {
		return "", err
	}
	if isValid := validate(normalizedTriples.(string)); !isValid {
		return "", errors.New("invalid_triples_found")
	}
	return normalizedTriples.(string), nil
}

func validate(doc string) bool {
	var (
		isValid bool = true
	)
	triples := strings.Split(doc, "\n")

	for _, v := range triples {
		_, err := ld.ParseNQuads(v)
		if err != nil {
			if !strings.Contains(err.Error(), "error while parsing N-Quads; invalid quad. line:") {
				return false
			}
			isValid = false
			continue
		}
	}
	return isValid
}
