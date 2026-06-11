package types

import (
	"encoding/json"
	"testing"
)

func TestBerachainDepositTxUnmarshal(t *testing.T) {
	raw := `{"type":"0x7e","chainId":"0x138de","to":"0xd2f19a79b026fb636a7c300bf5947df113940761","nonce":"0x1512f0a","gas":"0x1c9c380","gasPrice":"0x2f","input":"0x60644a6b","value":"0x0","maxFeePerGas":"0x2f","maxPriorityFeePerGas":"0x0","v":"0x0","r":"0x0","s":"0x0","hash":"0x6220b1be4b9c814d6a2ad89a8ee4a322276b5589becd74f4eb68a0e60cd07917","from":"0xfffffffffffffffffffffffffffffffffffffffe"}`
	var tx Transaction
	if err := json.Unmarshal([]byte(raw), &tx); err != nil {
		t.Fatalf("unmarshal berachain deposit tx: %v", err)
	}
	if tx.Type() != DepositTxType {
		t.Fatalf("type = %d, want %d", tx.Type(), DepositTxType)
	}
	if _, err := tx.MarshalJSON(); err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
}
