package types

import (
	"bytes"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/modules/core/24-host"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

var _ exported.Misbehaviour = &Misbehaviour{}

// ClientType is a Multisig light client.
func (misbehaviour Misbehaviour) ClientType() string {
	return TrustedEthereum
}

// GetClientID returns the ID of the client that committed a misbehaviour.
func (misbehaviour Misbehaviour) GetClientID() string {
	return misbehaviour.ClientId
}

// Type implements Evidence interface.
func (misbehaviour Misbehaviour) Type() string {
	return exported.TypeClientMisbehaviour
}

// GetHeight returns the sequence at which misbehaviour occurred.
// Return exported.Height to satisfy interface
func (misbehaviour Misbehaviour) GetHeight() exported.Height {
	return misbehaviour.Header1.Height
}

// ValidateBasic implements Evidence interface.
func (misbehaviour Misbehaviour) ValidateBasic() error {
	if misbehaviour.Header1 == nil {
		return sdkerrors.Wrap(ErrInvalidHeader, "misbehaviour Header1 cannot be nil")
	}
	if misbehaviour.Header2 == nil {
		return sdkerrors.Wrap(ErrInvalidHeader, "misbehaviour Header2 cannot be nil")
	}

	if err := host.ClientIdentifierValidator(misbehaviour.ClientId); err != nil {
		return sdkerrors.Wrap(err, "invalid client identifier for Multisig")
	}

	if err := misbehaviour.Header1.ValidateBasic(); err != nil {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour,
			sdkerrors.Wrap(err, "header 1 failed validation").Error(),
		)
	}
	if err := misbehaviour.Header2.ValidateBasic(); err != nil {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour,
			sdkerrors.Wrap(err, "header 2 failed validation").Error(),
		)
	}
	// Ensure that Height1 height is equal to Height2
	if !misbehaviour.Header1.GetHeight().EQ(misbehaviour.Header2.GetHeight()) {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 height is not as same as Header2 height (%s != %s)", misbehaviour.Header1.GetHeight(), misbehaviour.Header2.GetHeight())
	}
	// Ensure that Height1 timestamp is greater than or equal to timestamp
	if misbehaviour.Header1.GetTimestamp() < misbehaviour.Header2.GetTimestamp() {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 timestamp is less than Header2 timestamp (%d < %d)", misbehaviour.Header1.GetTimestamp(), misbehaviour.Header2.GetTimestamp())
	}

	// misbehaviour signatures cannot be identical
	if bytes.Equal(misbehaviour.Header1.Signature, misbehaviour.Header2.Signature) {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "misbehaviour signatures cannot be equal")
	}

	// message data signed cannot be identical.
	// XXX using sign bytes may be better
	pubkey1, err := misbehaviour.Header1.GetPubKey()
	if err != nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "invalid misbehaviour new public key")
	}
	pubkey2, err := misbehaviour.Header1.GetPubKey()
	if err != nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "invalid misbehaviour new public key")
	}

	if bytes.Equal(misbehaviour.Header1.AccountProof, misbehaviour.Header2.AccountProof) &&
		bytes.Equal(misbehaviour.Header1.StateRoot, misbehaviour.Header2.StateRoot) &&
		(misbehaviour.Header1.NewPublicKey == nil || pubkey1.Equals(pubkey2)) &&
		misbehaviour.Header1.NewDiversifier == misbehaviour.Header2.NewDiversifier {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "misbehaviour signature data must be signed over different messages")
	}
	return nil
}
