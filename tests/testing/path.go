package ibctesting

import (
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

// Path contains two endpoints representing two Chains connected over IBC
type Path struct {
	EndpointA *Endpoint
	EndpointB *Endpoint
}

// NewPath constructs an endpoint for each chain using the default values
// for the endpoints. Each endpoint is updated to have a pointer to the
// counterparty endpoint.
func NewPath(chainA, chainB types.TestChainI) *Path {
	endpointA := NewDefaultEndpoint(chainA)
	endpointB := NewDefaultEndpoint(chainB)

	endpointA.Counterparty = endpointB
	endpointB.Counterparty = endpointA

	return &Path{
		EndpointA: endpointA,
		EndpointB: endpointB,
	}
}
