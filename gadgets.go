package bgn

import (
	"fmt"
	"math/big"
)

// DecryptionProof is a proof that a ciphertext
// decrypts to Value
type DecryptionProof struct {
	Value      *big.Int
	Randomness *big.Int
}

// NewDecryptionProof constructs a new proof for value v and randomness r
func NewDecryptionProof(v *big.Int, r *big.Int) *DecryptionProof {
	return &DecryptionProof{
		v, r,
	}
}

// CheckDecryptionProof outputs true if the proof is valid for the ciphertext ct
func (pk *PublicKey) CheckDecryptionProof(ct *Ciphertext, proof *DecryptionProof) bool {

	res := pk.EncryptWithRandomness(proof.Value, proof.Randomness)

	fmt.Println(ct.C)
	fmt.Println(res.C)

	return ct.C.Equals(res.C)
}
