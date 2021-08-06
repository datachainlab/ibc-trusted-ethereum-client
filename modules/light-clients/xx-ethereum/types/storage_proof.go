package types

import (
	"bytes"
	fmt "fmt"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// VerifyEthAccountProof verifies an Ethereum account proof against the StateRoot.
// It does not verify the storage proof(s).
func VerifyEthAccountProof(proof [][]byte, stateRoot common.Hash, addressBytes []byte) ([]byte, error) {
	return verifyProof(stateRoot, addressBytes, proof)
}

// VerifyEthStorageProof verifies an Ethereum storage proof against the StateRoot.
// It does not verify the account proof against the Ethereum StateHash.
func VerifyEthStorageProof(proof [][]byte, storageHash common.Hash, key, value []byte) error {
	var err error
	v := []byte{}
	if len(value) != 0 {
		v, err = rlp.EncodeToBytes(value)
		if err != nil {
			return err
		}
	}
	return VerifyProof(storageHash, key, v, proof)
}

// VerifyProof verifies that the path generated from key, following the nodes
// in proof leads to a leaf with value, where the hashes are correct up to the
// rootHash.
// WARNING: When the value is not found, `eth_getProof` will return "0x0" at
// the StorageProof `value` field.  In order to verify the proof of non
// existence, you must set `value` to nil, *not* the RLP encoding of 0 or null
// (which would be 0x80).
func VerifyProof(rootHash common.Hash, key []byte, value []byte, proof [][]byte) error {
	res, err := verifyProof(rootHash, key, proof)
	if err != nil {
		return err
	}

	if !bytes.Equal(value, res) {
		return sdkerrors.Wrapf(ErrInvalidProof,
			"proof did not commit to expected value: %X, got: %X. Please ensure proof was submitted with correct proofHeight and to the correct chain.",
			value, res)
	}
	return nil
}

func verifyProof(rootHash common.Hash, key []byte, proof [][]byte) ([]byte, error) {
	proofDB := NewMemDB()
	// each node is RLP-serialized
	for _, node := range proof {
		k := crypto.Keccak256(node)
		proofDB.Put(k, node)
	}
	path := crypto.Keccak256(key)

	return trie.VerifyProof(rootHash, path, proofDB)
}

// MemDB is an ethdb.KeyValueReader implementation which is not thread safe and
// assumes that all keys are common.Hash.
type MemDB struct {
	kvs map[common.Hash][]byte
}

// NewMemDB creates a new empty MemDB
func NewMemDB() *MemDB {
	return &MemDB{
		kvs: make(map[common.Hash][]byte),
	}
}

// Has returns true if the MemBD contains the key
func (m *MemDB) Has(key []byte) (bool, error) {
	h := common.BytesToHash(key)
	_, ok := m.kvs[h]
	return ok, nil
}

// Get returns the value of the key, or nil if it's not found
func (m *MemDB) Get(key []byte) ([]byte, error) {
	h := common.BytesToHash(key)
	value, ok := m.kvs[h]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return value, nil
}

// Put sets or updates the value at key
func (m *MemDB) Put(key []byte, value []byte) {
	h := common.BytesToHash(key)
	m.kvs[h] = value
}
