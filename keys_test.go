package ldproofs_test

import (
	"fmt"
	"testing"

	"github.com/gossif/ldproofs"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigning(t *testing.T) {
	type testCases struct {
		description   string
		inputValue    string
		expectedError string
	}
	for _, scenario := range []testCases{
		{description: "method", inputValue: `{
			"kty": "OKP",
			"crv": "Ed25519",
			"x": "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			"d": "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE"
		  }`, expectedError: ""},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			jwkKey, err := jwk.ParseKey([]byte(scenario.inputValue))
			require.NoError(t, err)
			keyAlgorithm, err := ldproofs.NewAlgorithm(jwkKey)
			require.NoError(t, err)

			signed, err := keyAlgorithm.Sign([]byte("hello world!"))
			assert.NoError(t, err)

			fmt.Println(string(signed))
		})
	}
}
