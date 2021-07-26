package types

import (
	ibctransfertypes "github.com/cosmos/ibc-go/modules/apps/transfer/types"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
)

const (
	DefaultChannelVersion        = ibctransfertypes.Version
	DefaultDelayPeriod    uint64 = 0
	DefaultPrefix                = "ibc"
	TransferPort                 = ibctransfertypes.ModuleName

	RelayerKeyIndex uint32 = 0
)

var (
	ConnectionVersion      = connectiontypes.ExportedVersionsToProto(connectiontypes.GetCompatibleVersions())[0]
	DefaultOpenInitVersion *connectiontypes.Version
)
