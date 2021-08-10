package types

import (
	"strings"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

var _ exported.Header = &Header{}

// ClientType defines that the Header is a Multisig.
func (Header) ClientType() string {
	return TrustedEthereum
}

// GetHeight returns the current height. It returns 0 if the ethereum
// header is nil.
//
// Return clientexported.Height to satisfy interface
// Revision number is always 0 for a trusted ethereum
func (h Header) GetHeight() exported.Height {
	return clienttypes.NewHeight(0, h.Height.RevisionHeight)
}

// GetPubKey unmarshals the new public key into a cryptotypes.PubKey type.
// An error is returned if the new public key is nil or the cached value
// is not a PubKey.
func (h Header) GetPubKey() (cryptotypes.PubKey, error) {
	if h.NewPublicKey == nil {
		return nil, sdkerrors.Wrap(ErrInvalidHeader, "header NewPublicKey cannot be nil")
	}

	publicKey, ok := h.NewPublicKey.GetCachedValue().(cryptotypes.PubKey)
	if !ok {
		return nil, sdkerrors.Wrap(ErrInvalidHeader, "header NewPublicKey is not cryptotypes.PubKey")
	}

	return publicKey, nil
}

// GetTimestamp returns the current block timestamp. It returns a zero time if
// the ethereum header is nil.
func (h Header) GetTimestamp() uint64 {
	return h.Timestamp
}

// ValidateBasic ensures that the sequence, signature and public key have all
// been initialized.
func (h Header) ValidateBasic() error {
	if h.AccountProof == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "ethereum account proof cannot be nil")
	}

	if h.StateRoot == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "ethereum state root cannot be nil")
	}

	if h.Timestamp == 0 {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "ethereum timestamp cannot be 0")
	}
	if h.NewDiversifier != "" && strings.TrimSpace(h.NewDiversifier) == "" {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "diversifier cannot contain only spaces")
	}

	if len(h.Signature) == 0 {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "signature cannot be empty")
	}

	newPublicKey, err := h.GetPubKey()
	if err != nil || newPublicKey == nil || len(newPublicKey.Bytes()) == 0 {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "new public key cannot be empty")
	}

	if h.Signature == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "ethereum signature cannot be nil")
	}

	return nil
}
