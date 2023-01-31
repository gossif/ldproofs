# Linked Data Proofs

The linked data signature and verification conforms with [W3C JSON Web Signatures for Data Integrity Proofs](https://www.w3.org/TR/vc-jws-2020/)

## Usage

To sign a document in a function. The ```jsonCredential``` must be the []byte of a json string. 

```
doc, err := ldproofs.NewDocument(jsonCredential)
if err !=nil {
    return err
}
suite := ldproofs.NewJSONWebSignature2020Suite()
suite.ParseSignatureKey(jsonKey)

err = doc.AddLinkedDataProof(ldproofs.WithSignatureSuite(suite), ldproofs.WithPurpose(ldproofs.AssertionMethod))
if err !=nil {
    return err
}
```

To verify a document in a function.

```
doc, err := ldproofs.NewDocument(jsonCredential)
if err !=nil {
    return err
}
suite := ldproofs.NewJSONWebSignature2020Suite()
suite.ParseVerificationKey(jsonKey)

err = doc.VerifyLinkedDataProof(ldproofs.WithSignatureSuite(suite))
if err !=nil {
    return err
}
```

