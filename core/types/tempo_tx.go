package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

const TempoTxType = 0x76

// TempoTx is an opaque wrapper for Tempo's custom transaction type (0x76).
// We don't fully understand its structure, but we preserve the standard EVM
// fields so the transaction can pass through our pipeline. Sender recovery
// will fail (expected — the indexer skips such txs), but the block can still
// be deserialized.
type TempoTx struct {
	ChainId  *big.Int
	From     common.Address
	Nonce    uint64
	Gas      uint64
	GasPrice *big.Int
	To       *common.Address
	Value    *big.Int
	Data     []byte
}

func (tx *TempoTx) txType() byte          { return TempoTxType }
func (tx *TempoTx) chainID() *big.Int      { return tx.ChainId }
func (tx *TempoTx) accessList() AccessList { return nil }
func (tx *TempoTx) data() []byte           { return tx.Data }
func (tx *TempoTx) gas() uint64            { return tx.Gas }
func (tx *TempoTx) gasPrice() *big.Int {
	if tx.GasPrice != nil {
		return tx.GasPrice
	}
	return common.Big0
}
func (tx *TempoTx) gasTipCap() *big.Int { return tx.gasPrice() }
func (tx *TempoTx) gasFeeCap() *big.Int { return tx.gasPrice() }
func (tx *TempoTx) value() *big.Int {
	if tx.Value != nil {
		return tx.Value
	}
	return common.Big0
}
func (tx *TempoTx) nonce() uint64       { return tx.Nonce }
func (tx *TempoTx) to() *common.Address { return tx.To }

func (tx *TempoTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.Set(tx.gasPrice())
}

func (tx *TempoTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

func (tx *TempoTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *TempoTx) encode(b *bytes.Buffer) error { return nil }
func (tx *TempoTx) decode(input []byte) error    { return nil }

func (tx *TempoTx) sigHash(chainID *big.Int) common.Hash {
	return common.Hash{}
}

func (tx *TempoTx) copy() TxData {
	cpy := &TempoTx{
		From:  tx.From,
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
	}
	if tx.ChainId != nil {
		cpy.ChainId = new(big.Int).Set(tx.ChainId)
	}
	if tx.Value != nil {
		cpy.Value = new(big.Int).Set(tx.Value)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(tx.GasPrice)
	}
	return cpy
}
