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
if err != nil {
    return err
}
```

To verify a document in a function.

```
doc, err := ldproofs.NewDocument(jsonCredential)
if err != nil {
    return err
}
ldproofsType, err := doc.GetLinkedDataProofType()
if err != nil {
    // will get an error if proof or proof type is not found in the document
    return err
}
switch ldproofsType {
case "JsonWebSignature2020":
    suite := ldproofs.NewJSONWebSignature2020Suite()
    suite.ParseVerificationKey([]byte(rawkey))
default:
   return errors.New("linked data proofs type not supported")
}

err = doc.VerifyLinkedDataProof(ldproofs.WithSignatureSuite(suite))
if err != nil {
    return err
}
```

