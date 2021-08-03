package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// VerifySignature verifies if the the provided public key generated the signature
// over the given data. Single signature public keys are supported.
// The signature data type must correspond to the public key type. An error is
// returned if signature verification fails.
func VerifySignature(pubKey cryptotypes.PubKey, signBytes []byte, signature []byte) error {
	switch pubKey := pubKey.(type) {
	case multisig.PubKey:
		return sdkerrors.Wrapf(ErrSignatureVerificationFailed, "multisig pubkey is not supported")

	default:
		if !pubKey.VerifySignature(signBytes, signature) {
			return ErrSignatureVerificationFailed
		}
	}

	return nil
}

// HeaderSignBytes returns the sign bytes for verification of misbehaviour.
func HeaderSignBytes(
	cdc codec.BinaryCodec,
	header *Header,
) ([]byte, error) {
	signBytes := &Header{
		Height:         header.Height,
		ParentHash:     header.ParentHash,
		StateRoot:      header.StateRoot,
		Timestamp:      header.Timestamp,
		AccountProof:   header.AccountProof,
		Signature:      nil,
		NewPublicKey:   header.NewPublicKey,
		NewDiversifier: header.NewDiversifier,
	}

	return cdc.Marshal(signBytes)
}
