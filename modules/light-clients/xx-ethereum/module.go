package ethereum

import (
	"github.com/datachainlab/ibc-trusted-etheruem-client/modules/light-clients/xx-ethereum/types"
)

// Name returns the IBC client name
func Name() string {
	return types.SubModuleName
}
