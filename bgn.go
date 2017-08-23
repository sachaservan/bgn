package bgn

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"

	"github.com/Nik-U/pbc"
)

// PublicKey is the BGN public key used for encryption
// as well as performing homomorphic operations on ciphertexts
type PublicKey struct {
	Pairing *pbc.Pairing
	G1      *pbc.Element
	GT      *pbc.Element
	g       *pbc.Element
	h       *pbc.Element
	n       *big.Int
}

// SecretKey used for decryption of ciphertexts
type SecretKey struct {
	key *big.Int
}

// SecretKeyShare is a share of a secret key
type SecretKeyShare struct {
	share *big.Int
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
	max := big.NewInt(0).Div(sk.key, big.NewInt(int64(n)))

	// sum of all the shares
	sum := big.NewInt(0)

	// compute shares
	for i := 0; i < n-1; i++ {
		// create new random share
		next := newCryptoRandom(max)
		shares = append(shares, &SecretKeyShare{next})
		sum = big.NewInt(0).Add(sum, next)
	}

	// last share should be computed so as to
	// have all shares add up to sk
	last := big.NewInt(0).Sub(sk.key, sum)
	shares = append(shares, &SecretKeyShare{last})

	return pk, shares, err
}

// NewKeyGen creates a new public/private key pair of size bits
func NewKeyGen(bits int) (*PublicKey, *SecretKey, error) {

	if bits < 128 {
		return nil, nil, errors.New("key bits must be > 128")
	}

	var q1 *big.Int    // random prime
	var q2 *big.Int    // secret key (random prime)
	var n *big.Int     // n = r*q
	var g *pbc.Element // field element
	var h *pbc.Element // field element

	// generate a new random prime r
	q1, err := rand.Prime(rand.Reader, bits)

	// generate a new random prime q (this will be the secret key)
	q2, err = rand.Prime(rand.Reader, bits)

	if err != nil {
		return nil, nil, err
	}

	// compute the product of the primes
	n = big.NewInt(0).Mul(q1, q2)
	params := pbc.GenerateA1(n)

	if err != nil {
		return nil, nil, err
	}

	// create a new pairing with given params
	pairing := pbc.NewPairing(params)

	// generate the two multiplicative groups of
	// order n (using pbc pairing library)
	G1 := pairing.NewG1()
	GT := pairing.NewGT()

	// choose random point P in G1
	g = G1.Rand()

	// choose random Q in G1
	h = G1.NewFieldElement()
	h.PowBig(h, q2)

	// create public key with the generated groups
	pk := &PublicKey{pairing, G1, GT, g, h, n}

	// create secret key
	sk := &SecretKey{q1}

	return pk, sk, err
}

// Encrypt a given message m with the public key pk
func (pk *PublicKey) Encrypt(m *big.Int) *pbc.Element {

	r := newCryptoRandom(pk.n)

	G := pk.G1.NewFieldElement()
	H := pk.G1.NewFieldElement()

	G.PowBig(pk.g, m)
	H.PowBig(pk.h, r)

	C := pk.G1.NewFieldElement()
	C.Mul(G, H)

	return C
}

// Decrypt a level 1 (non-multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt(C *pbc.Element, pk *PublicKey) *big.Int {

	gsk := pk.G1.NewFieldElement()
	csk := pk.G1.NewFieldElement()
	aux := pk.G1.NewFieldElement()

	gsk.PowBig(pk.g, sk.key)
	csk.PowBig(C, sk.key)

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

	return m
}

// Decrypt2 a level 2 (multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt2(C *pbc.Element, pk *PublicKey) *big.Int {

	gsk := pk.GT.Pair(pk.g, pk.g)
	gsk.PowBig(gsk, sk.key)

	csk := C.NewFieldElement()
	csk.PowBig(C, sk.key)

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

	return m
}

// EAdd adds two level 1 (non-multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd(element1 *pbc.Element, element2 *pbc.Element) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.Mul(element1, element2)

	r := newCryptoRandom(pk.n)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.h, r)

	return result.Mul(result, h1)
}

// EAdd2 adds two level 2 (multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd2(element1 *pbc.Element, element2 *pbc.Element) *pbc.Element {

	result := pk.GT.NewFieldElement()
	result.Mul(element1, element2)

	r := newCryptoRandom(pk.n)
	h1 := pk.GT.Pair(pk.h, pk.h)
	h1.PowBig(h1, r)

	return result.Mul(result, h1)
}

// EMultC multiplies a level 1 (non-multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC(element1 *pbc.Element, constant *big.Int) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.MulBig(element1, constant)

	r := newCryptoRandom(pk.n)
	h1 := pk.G1.NewFieldElement()
	h1.MulBig(pk.h, r)

	return result.Mul(result, h1)
}

// EMultC2 multiplies a level 2 (multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC2(element1 *pbc.Element, constant *big.Int) *pbc.Element {

	result := pk.GT.NewFieldElement()
	result.MulBig(element1, constant)

	r := newCryptoRandom(pk.n)
	h1 := pk.GT.Pair(pk.h, pk.h)
	h1.PowBig(h1, r)

	return result.Mul(result, h1)
}

// EMult multiplies two level 1 (non-multiplied) ciphertext together and returns the result
func (pk *PublicKey) EMult(element1 *pbc.Element, element2 *pbc.Element) *pbc.Element {

	result := pk.GT.NewFieldElement()
	result = result.Pair(element1, element2)

	r := newCryptoRandom(pk.n)
	h1 := pk.Pairing.NewGT().Pair(pk.h, pk.h)
	h1.PowBig(h1, r)

	return result.Mul(result, h1)
}

// generates a new random number < max
func newCryptoRandom(max *big.Int) *big.Int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Println(err)
	}

	return rand
}
