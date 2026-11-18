package types

import (
	"math/big"
	"testing"
)

func TestTransactionMint(t *testing.T) {
	tests := []struct {
		name  string
		inner TxData
		want  *big.Int
	}{
		{
			name:  "legacy transaction",
			inner: &LegacyTx{},
			want:  nil,
		},
		{
			name:  "dynamic fee transaction",
			inner: &DynamicFeeTx{},
			want:  nil,
		},
		{
			name:  "deposit without mint",
			inner: &DepositTx{Mint: nil},
			want:  nil,
		},
		{
			name:  "deposit with mint",
			inner: &DepositTx{Mint: big.NewInt(1)},
			want:  big.NewInt(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := NewTx(tt.inner)
			got := tx.Mint()
			if got == nil && tt.want != nil {
				t.Fatalf("Mint() = nil, want %v", tt.want)
			}
			if got != nil && tt.want == nil {
				t.Fatalf("Mint() = %v, want nil", got)
			}
			if got != nil && got.Cmp(tt.want) != 0 {
				t.Fatalf("Mint() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("returned value is a copy", func(t *testing.T) {
		tx := NewTx(&DepositTx{Mint: big.NewInt(7)})
		got := tx.Mint()
		got.SetInt64(99)
		if tx.Mint().Cmp(big.NewInt(7)) != 0 {
			t.Fatalf("mutating the returned value changed the transaction: got %v, want 7", tx.Mint())
		}
	})
}
