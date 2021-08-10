package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const (
	ModuleName = "trusted ethereum"
)

var (
	ErrInvalidChainID              = sdkerrors.Register(ModuleName, 2, "invalid chain-id")
	ErrInvalidHeaderHeight         = sdkerrors.Register(ModuleName, 3, "invalid header height")
	ErrInvalidHeader               = sdkerrors.Register(ModuleName, 4, "invalid header")
	ErrInvalidSequence             = sdkerrors.Register(ModuleName, 5, "invalid sequence")
	ErrInvalidSignatureAndData     = sdkerrors.Register(ModuleName, 6, "invalid signature and data")
	ErrSignatureVerificationFailed = sdkerrors.Register(ModuleName, 7, "signature verification failed")
	ErrInvalidProof                = sdkerrors.Register(ModuleName, 8, "invalid proof")
	ErrInvalidDataType             = sdkerrors.Register(ModuleName, 9, "invalid data type")
	ErrProcessedTimeNotFound       = sdkerrors.Register(ModuleName, 10, "processed time not found")
	ErrProcessedHeightNotFound     = sdkerrors.Register(ModuleName, 11, "processed height not found")
	ErrDelayPeriodNotPassed        = sdkerrors.Register(ModuleName, 12, "packet-specified delay period has not been reached")
)
