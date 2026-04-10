package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// MorphL1MessageTxType is Morph's custom L1 message transaction type.
const MorphL1MessageTxType = 0x7f

// MorphL1MessageTx is an opaque wrapper for Morph's L1 message transaction type (0x7f).
// We preserve standard EVM fields so the transaction can round-trip through JSON
// marshal/unmarshal. Sender recovery is not supported — the downstream consumer
// (bchain-alerts) has a tx-type allowlist that skips 0x7f gracefully.
type MorphL1MessageTx struct {
	ChainId  *big.Int
	From     common.Address
	Nonce    uint64
	Gas      uint64
	GasPrice *big.Int
	To       *common.Address
	Value    *big.Int
	Data     []byte
}

func (tx *MorphL1MessageTx) txType() byte          { return MorphL1MessageTxType }
func (tx *MorphL1MessageTx) chainID() *big.Int {
	if tx.ChainId != nil {
		return tx.ChainId
	}
	return common.Big0
}
func (tx *MorphL1MessageTx) accessList() AccessList { return nil }
func (tx *MorphL1MessageTx) data() []byte           { return tx.Data }
func (tx *MorphL1MessageTx) gas() uint64            { return tx.Gas }
func (tx *MorphL1MessageTx) gasPrice() *big.Int {
	if tx.GasPrice != nil {
		return tx.GasPrice
	}
	return common.Big0
}
func (tx *MorphL1MessageTx) gasTipCap() *big.Int { return tx.gasPrice() }
func (tx *MorphL1MessageTx) gasFeeCap() *big.Int { return tx.gasPrice() }
func (tx *MorphL1MessageTx) value() *big.Int {
	if tx.Value != nil {
		return tx.Value
	}
	return common.Big0
}
func (tx *MorphL1MessageTx) nonce() uint64       { return tx.Nonce }
func (tx *MorphL1MessageTx) to() *common.Address { return tx.To }

func (tx *MorphL1MessageTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.Set(tx.gasPrice())
}

func (tx *MorphL1MessageTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

func (tx *MorphL1MessageTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *MorphL1MessageTx) encode(b *bytes.Buffer) error { return nil }
func (tx *MorphL1MessageTx) decode(input []byte) error    { return nil }

func (tx *MorphL1MessageTx) sigHash(chainID *big.Int) common.Hash {
	return common.Hash{}
}

func (tx *MorphL1MessageTx) copy() TxData {
	cpy := &MorphL1MessageTx{
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
