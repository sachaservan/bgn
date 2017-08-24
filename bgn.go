package bgn

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
	"strconv"
	"strings"

	"github.com/Nik-U/pbc"
)

type Plaintext struct {
	M           *big.Int // ciphertext (numerator if rational number)
	Denominator *big.Int // denominator (if rational number)
	IsRat       bool
}

type Ciphertext struct {
	C           *pbc.Element // ciphertext (numerator if rational number)
	Denominator *big.Int     // denominator (if rational number)
	IsRat       bool
}

type PartialDecrypt struct {
	Csk         *pbc.Element
	Gsk         *pbc.Element
	Denominator *big.Int
	IsRat       bool
}

// PublicKey is the BGN public key used for encryption
// as well as performing homomorphic operations on ciphertexts
type PublicKey struct {
	Pairing *pbc.Pairing
	G1      *pbc.Element
	P       *pbc.Element
	Q       *pbc.Element
	N       *big.Int
}

// SecretKey used for decryption of ciphertexts
type SecretKey struct {
	Key *big.Int
}

// SecretKeyShare is a share of a secret key
type SecretKeyShare struct {
	Share *big.Int
}

func NewPlaintextInt(m *big.Int) *Plaintext {
	return &Plaintext{m, big.NewInt(1), false}
}

func NewPlaintextRat(m *big.Rat) *Plaintext {
	return &Plaintext{m.Num(), m.Denom(), true}
}

// NewMPKeyGen generates a new public key and n shares of a secret key
func NewMPKeyGen(bits int, n int) (*PublicKey, []*SecretKeyShare, error) {

	// generate standard key pair
	var sk *SecretKey
	pk, sk, err := NewKeyGen(bits)

	if err != nil {
		return nil, nil, err
	}

	// secret key shares
	var shares []*SecretKeyShare

	// max value of each share (no bigger than sk/n)
	max := big.NewInt(0).Div(sk.Key, big.NewInt(int64(n)))

	// sum of all the shares
	sum := big.NewInt(0)

	// compute shares
	for i := 0; i < n-1; i++ {
		// create new random share
		next := newCryptoRandom(max)
		shares = append(shares, &SecretKeyShare{next})
		sum.Add(sum, next)
	}

	// last share should be computed so as to
	// have all shares add up to sk
	last := sum.Sub(sk.Key, sum)
	shares = append(shares, &SecretKeyShare{last})

	return pk, shares, err
}

// NewKeyGen creates a new public/private key pair of size bits
func NewKeyGen(bits int) (*PublicKey, *SecretKey, error) {

	if bits < 32 {
		return nil, nil, errors.New("key bits must be > 32")
	}

	var q1 *big.Int    // random prime
	var q2 *big.Int    // secret key (random prime)
	var N *big.Int     // n = r*q
	var P *pbc.Element // field element
	var Q *pbc.Element // field element

	// generate a new random prime r
	q1, err := rand.Prime(rand.Reader, bits)

	// generate a new random prime q (this will be the secret key)
	q2, err = rand.Prime(rand.Reader, bits)

	if err != nil {
		return nil, nil, err
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
	l, err := parseLFromParams(params)

	// choose random point P in G1
	P = G1.Rand()
	P.PowBig(P, l)

	// choose random Q in G1
	Q = G1.NewFieldElement()
	Q.PowBig(P, newCryptoRandom(N))
	Q.PowBig(Q, q2)

	// create public key with the generated groups
	pk := &PublicKey{pairing, G1, P, Q, N}

	// create secret key
	sk := &SecretKey{q1}

	return pk, sk, err
}

// Encrypt a given plaintext (integer or rational) with the public key pk
func (pk *PublicKey) Encrypt(plaintext *Plaintext) *Ciphertext {

	m := plaintext.M
	d := plaintext.Denominator
	if plaintext.IsRat {
		// TODO: better hiding factor
		u := big.NewInt(1) //newCryptoRandom(big.NewInt(A LARGE NUMBER HERE))
		m.Mul(m, u)
		d.Mul(d, u)
	}

	r := newCryptoRandom(pk.N)

	G := pk.G1.NewFieldElement()
	H := pk.G1.NewFieldElement()

	G.PowBig(pk.P, m)
	H.PowBig(pk.Q, r)

	C := pk.G1.NewFieldElement()
	C.Mul(G, H)

	return &Ciphertext{C, d, plaintext.IsRat}
}

// Decrypt a level 1 (non-multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt(ct *Ciphertext, pk *PublicKey) *Plaintext {

	gsk := pk.G1.NewFieldElement()
	csk := pk.G1.NewFieldElement()
	aux := pk.G1.NewFieldElement()

	gsk.PowBig(pk.P, sk.Key)
	csk.PowBig(ct.C, sk.Key)

	aux.Set(gsk)

	// brute force compute the discrete log
	// TODO: use kangaroo!
	m := big.NewInt(1)

	for {
		if aux.Equals(csk) {
			break
		}

		aux = aux.Mul(aux, gsk)
		m = m.Add(m, big.NewInt(1))
	}

	return &Plaintext{m, ct.Denominator, ct.IsRat}
}

// Decrypt2 a level 2 (multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt2(ct *Ciphertext, pk *PublicKey) *Plaintext {

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk.PowBig(gsk, sk.Key)

	csk := ct.C.NewFieldElement()
	csk.PowBig(ct.C, sk.Key)

	aux := gsk.NewFieldElement()
	aux.Set(gsk)

	// brute force compute the discrete log
	// TODO: use kangaroo!
	m := big.NewInt(1)

	for {
		if aux.Equals(csk) {
			break
		}

		aux = aux.Mul(aux, gsk)
		m = m.Add(m, big.NewInt(1))
	}

	return &Plaintext{m, ct.Denominator, ct.IsRat}
}

// EAdd adds two level 1 (non-multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	if (ct1.IsRat || ct2.IsRat) && ct1.Denominator.Cmp(ct2.Denominator) != 0 {

		// compute common denominator
		ct1a := pk.EMultC(ct1, ct2.Denominator)
		ct2a := pk.EMultC(ct2, ct1.Denominator)
		ct1a.Denominator.Mul(ct1.Denominator, ct2.Denominator)
		ct2a.Denominator.Set(ct1a.Denominator)
		ct1a.IsRat = true
		ct2a.IsRat = true
		// add the two ciphertexts now that they have a common denominator
		return pk.EAdd(ct1a, ct2a)
	}

	result := pk.G1.NewFieldElement()
	result.Mul(ct1.C, ct2.C)

	r := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, r)

	c := result.Mul(result, h1)
	return &Ciphertext{c, ct1.Denominator, (ct1.IsRat || ct2.IsRat)}
}

// EAdd2 adds two level 2 (multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd2(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	if (ct1.IsRat || ct2.IsRat) && ct1.Denominator.Cmp(ct2.Denominator) != 0 {

		// compute common denominator
		ct1a := pk.EMultC2(ct1, ct2.Denominator)
		ct2a := pk.EMultC2(ct2, ct1.Denominator)
		ct1a.Denominator.Mul(ct1.Denominator, ct2.Denominator)
		ct2a.Denominator.Mul(ct2.Denominator, ct1.Denominator)
		ct1a.IsRat = true
		ct2a.IsRat = true
		// add the two ciphertexts now that they have a common denominator
		return pk.EAdd2(ct1a, ct2a)
	}

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Mul(ct1.C, ct2.C)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	result.Mul(result, pair)

	return &Ciphertext{result, ct1.Denominator, (ct1.IsRat || ct2.IsRat)}
}

// EMultC multiplies a level 1 (non-multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC(ct *Ciphertext, constant *big.Int) *Ciphertext {

	result := pk.G1.NewFieldElement()
	result.MulBig(ct.C, constant)

	r := newCryptoRandom(pk.N)
	q := pk.G1.NewFieldElement()
	q.MulBig(pk.Q, r)

	result.Mul(result, q)
	return &Ciphertext{result, ct.Denominator, ct.IsRat}
}

// EMultC2 multiplies a level 2 (multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC2(ct *Ciphertext, constant *big.Int) *Ciphertext {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.MulBig(ct.C, constant)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	result.Mul(result, pair)
	return &Ciphertext{result, ct.Denominator, ct.IsRat}
}

// EMult multiplies two level 1 (non-multiplied) ciphertext together and returns the result
func (pk *PublicKey) EMult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	if (ct1.IsRat || ct2.IsRat) && ct1.Denominator.Cmp(ct2.Denominator) != 0 {

		// compute common denominator
		ct1a := ct1
		ct2a := ct2
		ct1a.Denominator.Mul(ct1a.Denominator, ct2a.Denominator)
		ct2a.Denominator = ct1a.Denominator
		ct1a.IsRat = true
		ct2a.IsRat = true

		return pk.EMult(ct1a, ct2a)
	}

	result := pk.Pairing.NewGT().NewFieldElement()
	result = result.Pair(ct1.C, ct2.C)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	result.Mul(result, pair)
	return &Ciphertext{result, ct1.Denominator, ct1.IsRat}
}

func (sk *SecretKeyShare) PartialDecrypt(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	csk := pk.G1.NewFieldElement()
	gsk := pk.G1.NewFieldElement()

	csk.PowBig(ct.C, sk.Share)
	gsk.PowBig(pk.P, sk.Share)

	return &PartialDecrypt{csk, gsk, ct.Denominator, ct.IsRat}
}

func (sk *SecretKeyShare) PartialDecrypt2(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk.PowBig(gsk, sk.Share)

	csk := ct.C.NewFieldElement()
	csk.PowBig(ct.C, sk.Share)

	return &PartialDecrypt{csk, gsk, ct.Denominator, ct.IsRat}
}

func CombinedShares(shares []*PartialDecrypt, pk *PublicKey) *Plaintext {

	csk := shares[0].Csk.NewFieldElement()
	gsk := shares[0].Gsk.NewFieldElement()

	csk.Set(shares[0].Csk)
	gsk.Set(shares[0].Gsk)

	for index, share := range shares {
		if index == 0 {
			continue
		}

		csk.Mul(csk, share.Csk)
		gsk.Mul(gsk, share.Gsk)
	}

	denominator := shares[0].Denominator
	isRat := shares[0].IsRat

	aux := gsk.NewFieldElement()
	aux.Set(gsk)

	// brute force compute the discrete log
	// TODO: use kangaroo!
	m := big.NewInt(1)

	for {
		if aux.Equals(csk) {
			break
		}

		aux = aux.Mul(aux, gsk)
		m = m.Add(m, big.NewInt(1))
	}

	return &Plaintext{m, denominator, isRat}
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
func parseLFromParams(params *pbc.Params) (*big.Int, error) {

	paramsStr := params.String()
	lStr := paramsStr[strings.Index(paramsStr, "l")+2 : len(paramsStr)-1]
	lInt, err := strconv.ParseInt(lStr, 10, 64)
	if err != nil {
		return nil, err
	}

	return big.NewInt(lInt), nil
}

func (c *Ciphertext) String() string {

	if c.IsRat {
		return c.C.String() + " / " + c.Denominator.String()
	}
	return c.C.String()
}

func (p *Plaintext) String() string {

	if p.IsRat {
		floatNum := big.NewFloat(0).SetInt(p.M)
		floatDenom := big.NewFloat(0).SetInt(p.Denominator)

		result := big.NewFloat(0).Quo(floatNum, floatDenom)
		return result.String() + "f"
	}
	return p.M.String()
}
