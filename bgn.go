package bgn

import (
	"crypto/rand"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/Nik-U/pbc"
)

// PublicKey is the BGN public key used for encryption
// as well as performing homomorphic operations on Ciphertexts
type PublicKey struct {
	Pairing       *pbc.Pairing // pairing between G1 and GT
	G1            *pbc.Element // G1 group
	P             *pbc.Element // generator of G1 ang GT
	Q             *pbc.Element // generator of subgroup H
	N             *big.Int     // product of two primes
	T             *big.Int     // message space T
	PolyBase      int          // PolyCiphertext polynomial encoding base
	FPScaleBase   int          // fixed point encoding scale base
	FPPrecision   float64      // min error tolerance for fixed point encoding
	Deterministic bool         // whether or not the homomorphic operations are deterministic
	mu            sync.Mutex   // mutex for parallel executions (pbc is not thread-safe)
}

// SecretKey used for decryption of PolyCiphertexts
type SecretKey struct {
	Key      *big.Int
	PolyBase int
}

// NewKeyGen creates a new public/private key pair of size bits
func NewKeyGen(keyBits int, T *big.Int, polyBase int, fpScaleBase int, fpPrecision float64, deterministic bool) (*PublicKey, *SecretKey, error) {

	if keyBits < 16 {
		panic("key bits must be >= 16 bits in length")
	}

	var q1 *big.Int    // random prime
	var q2 *big.Int    // secret key (random prime)
	var N *big.Int     // n = r*q
	var P *pbc.Element // field element
	var Q *pbc.Element // field element

	// generate a new random prime r
	q1, err := rand.Prime(rand.Reader, keyBits)

	// generate a new random prime q (this will be the secret key)
	q2, err = rand.Prime(rand.Reader, keyBits)

	if err != nil {
		return nil, nil, err
	}

	if q1.Cmp(T) < 0 || q2.Cmp(T) < 0 {
		panic("Message space is greater than the group order!")
	}

	// compute the product of the primes
	N = big.NewInt(0).Mul(q1, q2)
	params := pbc.GenerateA1(N)

	if err != nil {
		return nil, nil, err
	}

	// create a new pairing with given params
	pairing := pbc.NewPairing(params)

	// generate the two multiplicative groups of
	// order n (using pbc pairing library)
	G1 := pairing.NewG1()

	// obtain l generated from the pbc library
	// is a "small" number s.t. p + 1 = l*n
	l, err := parseLFromPBCParams(params)

	// choose random point P in G which becomes a generator for G of order N
	P = G1.Rand()
	P.PowBig(P, big.NewInt(0).Mul(l, big.NewInt(4)))
	// Make P a generate for the subgroup of order q1T

	// choose random Q in G1
	Q = G1.NewFieldElement()
	Q.PowBig(P, newCryptoRandom(N))
	Q.PowBig(Q, q2)

	// create public key with the generated groups
	pk := &PublicKey{pairing, G1, P, Q, N, T, polyBase, fpScaleBase, fpPrecision, deterministic, sync.Mutex{}}

	// create secret key
	sk := &SecretKey{q1, polyBase}

	if err != nil {
		panic("Couldn't generate key params!")
	}

	pk.computeEncodingTable()

	return pk, sk, err
}

// Decrypt uses the secret key to recover the encrypted value
// throws an error if decryption fails
func (sk *SecretKey) Decrypt(ct *Ciphertext, pk *PublicKey) (*big.Int, error) {
	return sk.decrypt(ct, pk, false)
}

// DecryptFailSafe returns zero if encryption fails rather than throwing an error
func (sk *SecretKey) DecryptFailSafe(ct *Ciphertext, pk *PublicKey) *big.Int {
	v, err := sk.decrypt(ct, pk, false)
	if err != nil {
		return big.NewInt(0)
	}
	return v
}

func (sk *SecretKey) decrypt(ct *Ciphertext, pk *PublicKey, failed bool) (*big.Int, error) {
	gsk := pk.G1.NewFieldElement()
	csk := ct.C.NewFieldElement()

	gsk.PowBig(pk.P, sk.Key)
	csk.PowBig(ct.C, sk.Key)

	// move to GT if decrypting L2 ciphertext
	if ct.L2 {
		gsk = pk.Pairing.NewGT().Pair(pk.P, pk.P)
		gsk.PowBig(gsk, sk.Key)
	}

	pt, err := pk.recoverMessage(gsk, csk, ct.L2)

	// if the decryption failed, then try decrypting
	// the inverse of the element as it encodes a negative value
	if err != nil && !failed {
		neg := pk.Neg(ct)
		dec, err := sk.decrypt(neg, pk, true)
		if err != nil {
			return nil, err
		}
		return big.NewInt(0).Mul(big.NewInt(-1), dec), nil
	}

	// failed to decrypt for some other reason
	if err != nil && failed {
		return nil, err
	}

	return pt, nil
}

// MultConst multiplies an encrypted value by a constant
func (pk *PublicKey) MultConst(c *Ciphertext, constant *big.Int) *Ciphertext {

	// handle the case of L1 and L2 ciphertext seperately
	if !c.L2 {
		res := c.C.NewFieldElement()
		res.PowBig(c.C, constant)

		if !pk.Deterministic {
			r := newCryptoRandom(pk.N)
			q := c.C.NewFieldElement()

			pk.mu.Lock()
			q.MulBig(pk.Q, r)
			pk.mu.Unlock()

			res.Mul(res, q)
		}
		return &Ciphertext{res, c.L2}
	}

	pk.mu.Lock()
	res := pk.Pairing.NewGT().NewFieldElement()
	pk.mu.Unlock()

	res.PowBig(c.C, constant)

	if !pk.Deterministic {
		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().NewFieldElement().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		res.Mul(res, pair)
	}

	return &Ciphertext{res, c.L2}
}

// Mult multiplies two encrypted values together, making the ciphertext level2
func (pk *PublicKey) Mult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	pk.mu.Lock()
	res := pk.Pairing.NewGT().NewFieldElement()
	pk.mu.Unlock()

	res.Pair(ct1.C, ct2.C)

	if !pk.Deterministic {
		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		res.Mul(res, pair)
	}

	return &Ciphertext{res, true}
}

func (pk *PublicKey) makeL2(ct *Ciphertext) *Ciphertext {
	result := pk.Pairing.NewGT().NewFieldElement()
	result.Pair(ct.C, pk.EncryptDeterministic(big.NewInt(1)).C)

	return &Ciphertext{result, true}
}

// EncryptDeterministic returns a deterministic (non randomized) ciphertext
// of the value x
func (pk *PublicKey) EncryptDeterministic(x *big.Int) *Ciphertext {

	G := pk.G1.NewFieldElement()
	G.PowBig(pk.P, x)

	return &Ciphertext{C: G, L2: false}
}

// Encrypt returns a ciphertext encrypting x
func (pk *PublicKey) Encrypt(x *big.Int) *Ciphertext {

	pk.mu.Lock()
	G := pk.G1.NewFieldElement()
	G.PowBig(pk.P, x)
	r := newCryptoRandom(pk.N)
	H := pk.G1.NewFieldElement()
	H.PowBig(pk.Q, r)
	C := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	return &Ciphertext{C.Mul(G, H), false}
}

// RecoverMessage finds the discrete logarithm to recover and returns the value (if found)
// if the value is too large, an error is thrown
func (pk *PublicKey) recoverMessage(gsk *pbc.Element, csk *pbc.Element, l2 bool) (*big.Int, error) {

	zero := gsk.NewFieldElement()

	if zero.Equals(csk) {
		return big.NewInt(0), nil
	}

	m, err := pk.getDL(csk, gsk, l2)

	if err != nil {
		return nil, err
	}
	return m, nil

}

// Sub homomorphically subtracts two encrypted values and returns the result
func (pk *PublicKey) Sub(coeff1 *Ciphertext, coeff2 *Ciphertext) *Ciphertext {

	ct1 := coeff1
	ct2 := coeff2

	if coeff1.L2 && !coeff2.L2 {
		ct2 = pk.makeL2(coeff2)
	}

	if !coeff1.L2 && coeff2.L2 {
		ct1 = pk.makeL2(coeff1)
	}

	if ct1.L2 != ct2.L2 {
		panic("Attempting to add ciphertexts at different levels")
	}

	if ct1.L2 && ct2.L2 {
		pk.mu.Lock()
		result := pk.Pairing.NewGT().NewFieldElement()
		pk.mu.Unlock()

		result.Div(ct1.C, ct2.C)

		if pk.Deterministic {
			return &Ciphertext{result, true} // don't hide with randomness
		}

		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)
		result.Mul(result, pair)
		return &Ciphertext{result, false}

	}

	pk.mu.Lock()
	result := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	result.Div(ct1.C, ct2.C)
	if pk.Deterministic {
		return &Ciphertext{C: result, L2: ct1.L2} // don't blind with randomness
	}

	rand := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()

	pk.mu.Lock()
	h1.PowBig(pk.Q, rand)
	pk.mu.Unlock()

	result.Mul(result, h1)
	return &Ciphertext{result, ct1.L2}
}

// Neg returns the additive inverse of the ciphertext
func (pk *PublicKey) Neg(c *Ciphertext) *Ciphertext {
	return pk.Sub(pk.encryptZero(), c)

}

// Add homomorphically adds two encrypted values and returns the result
func (pk *PublicKey) Add(coeff1 *Ciphertext, coeff2 *Ciphertext) *Ciphertext {

	ct1 := coeff1
	ct2 := coeff2

	if coeff1.L2 && !coeff2.L2 {
		ct2 = pk.makeL2(coeff2)
	}

	if !coeff1.L2 && coeff2.L2 {
		ct1 = pk.makeL2(coeff1)
	}

	if ct1.L2 && ct2.L2 {
		pk.mu.Lock()
		result := pk.Pairing.NewGT().NewFieldElement()
		pk.mu.Unlock()

		result.Mul(ct1.C, ct2.C)

		if pk.Deterministic {
			return &Ciphertext{result, ct1.L2}
		}

		r := newCryptoRandom(pk.N)

		pk.mu.Lock()
		pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
		pk.mu.Unlock()

		pair.PowBig(pair, r)

		result.Mul(result, pair)
		return &Ciphertext{result, ct1.L2}
	}

	pk.mu.Lock()
	result := pk.G1.NewFieldElement()
	pk.mu.Unlock()

	result.Mul(ct1.C, ct2.C)

	if pk.Deterministic {
		return &Ciphertext{result, ct1.L2}
	}

	rand := newCryptoRandom(pk.N)

	pk.mu.Lock()
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, rand)
	pk.mu.Unlock()

	result.Mul(result, h1)
	return &Ciphertext{result, ct1.L2}
}

func (pk *PublicKey) encryptZero() *Ciphertext {
	return pk.EncryptDeterministic(big.NewInt(0))
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}

// TOTAL HACK to access the generated "l" in the C struct
// which the PBC library holds. The golang wrapper has
// no means of accessing the struct variable without
// knowing the exact memory mapping. Better approach
// would be to either compute l on the fly or figure
// out the memory mapping between the C struct and
// golang equivalent
func parseLFromPBCParams(params *pbc.Params) (*big.Int, error) {

	paramsStr := params.String()
	lStr := paramsStr[strings.Index(paramsStr, "l")+2 : len(paramsStr)-1]
	lInt, err := strconv.ParseInt(lStr, 10, 64)
	if err != nil {
		return nil, err
	}

	return big.NewInt(lInt), nil
}
