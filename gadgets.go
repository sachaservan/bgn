package bgn

import (
	"crypto/sha256"
	"math/big"
)

// ProofOfPlaintextKnowledge is a proof that
// the value encrypted by the ciphertext is known
type ProofOfPlaintextKnowledge struct {
	Ct    *Ciphertext
	Nonce *Ciphertext
	DL    *big.Int
}

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

// NewProofOfPlaintextKnowledge generates a proof of plaintext knowledge for a ciphertext encrypting
// the value v with randomness z
func (pk *PublicKey) NewProofOfPlaintextKnowledge(sk *SecretKey, v *big.Int, z *big.Int) *ProofOfPlaintextKnowledge {
	nonce1 := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, z)                     // g^v * h^z = g^(v + Rzq)
	nonce := pk.EncryptWithRandomness(nonce1, big.NewInt(0)) // g^r * h^0 = g^(r)

	proof := &ProofOfPlaintextKnowledge{
		ct, nonce, nil,
	}

	nonce2 := hash(proof)
	DL := big.NewInt(0)
	DL.Add(DL, nonce1)                      // r
	DL.Add(DL, new(big.Int).Mul(nonce2, v)) // r + cv
	tmp := new(big.Int).Mul(pk.R, z)
	tmp.Mul(tmp, nonce2)                         // Rzc
	tmp.Mul(tmp, new(big.Int).Div(pk.N, sk.Key)) // Rzcq
	DL.Add(DL, tmp)                              //  r + cv + Rzcq
	DL.Mod(DL, pk.N)

	proof.DL = DL

	return proof
}

// CheckDecryptionProof outputs true if the proof is valid for the ciphertext ct
func (pk *PublicKey) CheckDecryptionProof(ct *Ciphertext, proof *DecryptionProof) bool {

	res := pk.EncryptWithRandomness(proof.Value, proof.Randomness)
	return ct.C.Equals(res.C)
}

// CheckProofOfPlaintextKnoewledge checks whether proof corresponds to a valid
// proof of plaintext knowledge for the ciphertext ct
func (pk *PublicKey) CheckProofOfPlaintextKnoewledge(ct *Ciphertext, proof *ProofOfPlaintextKnowledge) bool {

	nonce2 := hash(proof)

	res := ct.C.NewFieldElement()
	res.PowBig(ct.C, nonce2)    // g^vc * h^zc = g^(vc + Rzcq)
	res.Mul(res, proof.Nonce.C) // g^(r + vc + Rzcq)

	G := pk.P.NewFieldElement()
	G.PowBig(pk.P, proof.DL) // g^(r + vc + Rzcq)

	return G.Equals(res)
}

// hash computes the sha2 hash of the provided proof
func hash(proof *ProofOfPlaintextKnowledge) *big.Int {

	bytes := make([]byte, 0)

	bytes = append(bytes, proof.Ct.C.Bytes()...)
	bytes = append(bytes, proof.Nonce.C.Bytes()...)

	h := sha256.New()
	h.Write([]byte(bytes))
	hash := h.Sum(nil)

	return new(big.Int).SetBytes(hash)
}
