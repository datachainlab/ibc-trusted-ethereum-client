// Bridge package to expose types internals to tests in the types_test
// package.
package types

var (
	ExportKeccak256AbiEncodePacked = keccak256AbiEncodePacked
	ExportDecoreRLP                = decodeRLP
	ExportDecodeStorageHash        = decodeStorageHash
)
