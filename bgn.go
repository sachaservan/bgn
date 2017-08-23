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

// Encrypt a given message m with the public key pk
func (pk *PublicKey) Encrypt(m *big.Int) *pbc.Element {

	r := newCryptoRandom(pk.N)

	G := pk.G1.NewFieldElement()
	H := pk.G1.NewFieldElement()

	G.PowBig(pk.P, m)
	H.PowBig(pk.Q, r)

	C := pk.G1.NewFieldElement()
	C.Mul(G, H)

	return C
}

// Decrypt a level 1 (non-multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt(C *pbc.Element, pk *PublicKey) *big.Int {

	gsk := pk.G1.NewFieldElement()
	csk := pk.G1.NewFieldElement()
	aux := pk.G1.NewFieldElement()

	gsk.PowBig(pk.P, sk.Key)
	csk.PowBig(C, sk.Key)

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

func (sk *SecretKeyShare) PartialDecrypt(C *pbc.Element, pk *PublicKey) (*pbc.Element, *pbc.Element) {

	csk := pk.G1.NewFieldElement()
	gsk := pk.G1.NewFieldElement()

	csk.PowBig(C, sk.Share)
	gsk.PowBig(pk.P, sk.Share)

	return csk, gsk
}

func (sk *SecretKeyShare) PartialDecrypt2(C *pbc.Element, pk *PublicKey) (*pbc.Element, *pbc.Element) {

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk.PowBig(gsk, sk.Share)

	csk := C.NewFieldElement()
	csk.PowBig(C, sk.Share)

	return csk, gsk
}

func CombinedShares(cskShares []*pbc.Element, gskShares []*pbc.Element, pk *PublicKey) *big.Int {

	csk := cskShares[0].NewFieldElement()
	gsk := gskShares[0].NewFieldElement()

	csk.Set(cskShares[0])
	for index, partial := range cskShares {
		if index == 0 {
			continue
		}

		csk.Mul(csk, partial)
	}

	gsk.Set(gskShares[0])
	for index, partial := range gskShares {
		if index == 0 {
			continue
		}

		gsk.Mul(gsk, partial)
	}

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

// Decrypt2 a level 2 (multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt2(C *pbc.Element, pk *PublicKey) *big.Int {

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk.PowBig(gsk, sk.Key)

	csk := C.NewFieldElement()
	csk.PowBig(C, sk.Key)

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

	r := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, r)

	return result.Mul(result, h1)
}

// EAdd2 adds two level 2 (multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd2(element1 *pbc.Element, element2 *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Mul(element1, element2)

	r := newCryptoRandom(pk.N)
	q := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	q.PowBig(q, r)

	return result.Mul(result, q)
}

// EMultC multiplies a level 1 (non-multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC(element1 *pbc.Element, constant *big.Int) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.MulBig(element1, constant)

	r := newCryptoRandom(pk.N)
	q := pk.G1.NewFieldElement()
	q.MulBig(pk.Q, r)

	return result.Mul(result, q)
}

// EMultC2 multiplies a level 2 (multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC2(element1 *pbc.Element, constant *big.Int) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.MulBig(element1, constant)

	r := newCryptoRandom(pk.N)
	q := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	q.PowBig(q, r)

	return result.Mul(result, q)
}

// EMult multiplies two level 1 (non-multiplied) ciphertext together and returns the result
func (pk *PublicKey) EMult(element1 *pbc.Element, element2 *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result = result.Pair(element1, element2)

	r := newCryptoRandom(pk.N)
	q := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	q.PowBig(q, r)

	return result.Mul(result, q)
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
