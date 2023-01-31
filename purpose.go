package ldproofs

type Purpose string

const (
	AssertionMethod      Purpose = "assertionMethod"
	Authentication       Purpose = "authentication"
	KeyAgreement         Purpose = "keyAgreement"
	CapabilityInvocation Purpose = "capabilityInvocation"
	CapabilityDelegation Purpose = "capabilityDelegation"
)

func (p Purpose) String() string {
	return string(p)
}
