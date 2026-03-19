package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

var ArbosAddress = common.HexToAddress("0xa4b05")
var ArbosStateAddress = common.HexToAddress("0xA4B05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
var ArbSysAddress = common.HexToAddress("0x64")
var ArbInfoAddress = common.HexToAddress("0x65")
var ArbAddressTableAddress = common.HexToAddress("0x66")
var ArbBLSAddress = common.HexToAddress("0x67")
var ArbFunctionTableAddress = common.HexToAddress("0x68")
var ArbosTestAddress = common.HexToAddress("0x69")
var ArbGasInfoAddress = common.HexToAddress("0x6c")
var ArbOwnerPublicAddress = common.HexToAddress("0x6b")
var ArbAggregatorAddress = common.HexToAddress("0x6d")
var ArbRetryableTxAddress = common.HexToAddress("0x6e")
var ArbStatisticsAddress = common.HexToAddress("0x6f")
var ArbOwnerAddress = common.HexToAddress("0x70")
var ArbWasmAddress = common.HexToAddress("0x71")
var ArbWasmCacheAddress = common.HexToAddress("0x72")
var NodeInterfaceAddress = common.HexToAddress("0xc8")
var NodeInterfaceDebugAddress = common.HexToAddress("0xc9")
var ArbDebugAddress = common.HexToAddress("0xff")

type arbitrumSigner struct{ Signer }

func NewArbitrumSigner(signer Signer) Signer {
	return arbitrumSigner{Signer: signer}
}

// Sender is handled by the global Sender() function in transaction_signing.go
// which short-circuits for all embedded-sender tx types before calling signer.Sender().
func (s arbitrumSigner) Sender(tx *Transaction) (common.Address, error) {
	return s.Signer.Sender(tx)
}

func (s arbitrumSigner) Equal(s2 Signer) bool {
	x, ok := s2.(arbitrumSigner)
	return ok && x.Signer.Equal(s.Signer)
}

func (s arbitrumSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	switch tx.inner.(type) {
	case *ArbitrumUnsignedTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumContractTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumDepositTx:
		return bigZero, bigZero, bigZero, nil
	case *DepositTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumInternalTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumRetryTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumSubmitRetryableTx:
		return bigZero, bigZero, bigZero, nil
	case *ArbitrumLegacyTxData:
		legacyData := tx.inner.(*ArbitrumLegacyTxData)
		fakeTx := NewTx(&legacyData.LegacyTx)
		return s.Signer.SignatureValues(fakeTx, sig)
	default:
		return s.Signer.SignatureValues(tx, sig)
	}
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s arbitrumSigner) Hash(tx *Transaction) common.Hash {
	if legacyData, isArbLegacy := tx.inner.(*ArbitrumLegacyTxData); isArbLegacy {
		fakeTx := NewTx(&legacyData.LegacyTx)
		return s.Signer.Hash(fakeTx)
	}
	return s.Signer.Hash(tx)
}
