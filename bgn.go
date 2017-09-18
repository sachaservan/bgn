package bgn

import (
	"crypto/rand"
	"log"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/Nik-U/pbc"
)

// PublicKey is the BGN public key used for encryption
// as well as performing homomorphic operations on ciphertexts
type PublicKey struct {
	Pairing     *pbc.Pairing // pairing between G1 and G2
	G1          *pbc.Element // G1 group
	P           *pbc.Element // generator of G1
	Q           *pbc.Element
	N           *big.Int // product of two primes
	T           *big.Int
	PolyBase    int
	FPPrecision int
}

// SecretKey used for decryption of ciphertexts
type SecretKey struct {
	Key      *big.Int
	PolyBase int
}

// NewKeyGen creates a new public/private key pair of size bits
func NewKeyGen(keyBits int, polyBase int, fpPrecision int) (*PublicKey, *SecretKey, error) {

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
	pk := &PublicKey{pairing, G1, P, Q, N, q2, polyBase, fpPrecision}

	// create secret key
	sk := &SecretKey{q1, polyBase}

	return pk, sk, err
}

// Encrypt a given plaintext (integer or rational) with the public key pk
func (pk *PublicKey) Encrypt(pt *Plaintext) *Ciphertext {

	size := len(pt.Coefficients)
	encryptedCoeffs := make([]*pbc.Element, size)

	for i, coeff := range pt.Coefficients {

		bigCoeff := big.NewInt(coeff)

		if coeff < 0 {
			bigCoeff.Add(pk.T, bigCoeff) // a^-1 = N-a
		}

		r := newCryptoRandom(pk.N)

		G := pk.G1.NewFieldElement()
		H := pk.G1.NewFieldElement()

		G.PowBig(pk.P, bigCoeff)
		H.PowBig(pk.Q, r)

		C := pk.G1.NewFieldElement()
		C.Mul(G, H)
		encryptedCoeffs[i] = C
	}

	return &Ciphertext{encryptedCoeffs, pt.ScaleFactor}
}

// Decrypt a level 1 (non-multiplied) ciphertext C using secret key sk
func (sk *SecretKey) Decrypt(ct *Ciphertext, pk *PublicKey) *Plaintext {

	size := len(ct.Coefficients)
	plaintextCoeffs := make([]int64, size)

	for i, coeff := range ct.Coefficients {

		gsk := pk.G1.NewFieldElement()
		csk := pk.G1.NewFieldElement()
		aux := pk.G1.NewFieldElement()
		zero := pk.G1.NewFieldElement()

		gsk.PowBig(pk.P, sk.Key)
		csk.PowBig(coeff, sk.Key)

		if zero.Equals(csk) {
			plaintextCoeffs[i] = 0
			continue
		}

		aux.Set(gsk)

		// brute force compute the discrete log
		// TODO: use kangaroo!
		m := big.NewInt(1)

		for {
			if aux.Equals(csk) {
				break
			}

			aux.Mul(aux, gsk)
			m.Add(m, big.NewInt(1))
		}

		plaintextCoeffs[i] = m.Int64()

		threshold := big.NewInt(0).Div(pk.T, big.NewInt(2))
		if m.Cmp(threshold) >= 1 {
			m.Sub(m, pk.T)
			plaintextCoeffs[i] = m.Int64()
		}
	}

	return &Plaintext{plaintextCoeffs, pk.PolyBase, ct.ScaleFactor}
}

// DecryptL2 a level 2 (multiplied) ciphertext C using secret key sk
func (sk *SecretKey) DecryptL2(ct *Ciphertext, pk *PublicKey) *Plaintext {

	size := len(ct.Coefficients)
	plaintextCoeffs := make([]int64, size)

	for i, coeff := range ct.Coefficients {

		gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
		gsk.PowBig(gsk, sk.Key)

		csk := coeff.NewFieldElement()
		csk.PowBig(coeff, sk.Key)

		aux := gsk.NewFieldElement()
		aux.Set(gsk)

		zero := pk.Pairing.NewGT().NewFieldElement()

		if zero.Equals(csk) {
			plaintextCoeffs[i] = 0
			continue
		}

		aux.Set(gsk)

		// brute force compute the discrete log
		// TODO: use kangaroo!
		m := big.NewInt(1)

		for {
			if aux.Equals(csk) {
				break
			}

			aux.Mul(aux, gsk)
			m.Add(m, big.NewInt(1))
		}

		plaintextCoeffs[i] = m.Int64()

		threshold := big.NewInt(0).Div(pk.T, big.NewInt(2))
		if m.Cmp(threshold) >= 1 {
			m.Sub(m, pk.T)
			plaintextCoeffs[i] = m.Int64()
		}
	}

	return &Plaintext{plaintextCoeffs, pk.PolyBase, ct.ScaleFactor}
}

// EAdd adds two level 1 (non-multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd(ciphertext1 *Ciphertext, ciphertext2 *Ciphertext) *Ciphertext {

	ct1 := ciphertext1
	ct2 := ciphertext2
	scaleFactor := ct1.ScaleFactor

	if ct1.ScaleFactor > ct2.ScaleFactor {
		diff := ct1.ScaleFactor - ct2.ScaleFactor
		newCoeffs := make([]*pbc.Element, len(ct2.Coefficients)+diff)

		var i int
		for i = 0; i < len(ct2.Coefficients); i++ {
			newCoeffs[i] = ct2.Coefficients[i]
		}

		for ; i < len(ct2.Coefficients)+diff; i++ {
			newCoeffs[i] = pk.encryptZero()
		}

		ct2.Coefficients = newCoeffs

	} else if ct2.ScaleFactor > ct1.ScaleFactor {
		// flip the ciphertexts
		return pk.EAdd(ciphertext2, ciphertext1)
	}

	degree := int(math.Max(float64(len(ct1.Coefficients)), float64(len(ct2.Coefficients))))
	result := make([]*pbc.Element, degree)

	for i := degree - 1; i >= 0; i-- {

		if i >= len(ct2.Coefficients) {
			result[i] = ct1.Coefficients[i]
			continue
		}

		if i >= len(ct1.Coefficients) {
			result[i] = ct2.Coefficients[i]
			continue
		}

		result[i] = pk.eAdd(ct1.Coefficients[i], ct2.Coefficients[i])
	}

	return &Ciphertext{result, scaleFactor}
}

func (pk *PublicKey) eAdd(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.Mul(coeff1, coeff2)

	rand := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, rand)

	return result.Mul(result, h1)
}

// EAddL2 adds two level 2 (multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAddL2(ciphertext1 *Ciphertext, ciphertext2 *Ciphertext) *Ciphertext {

	ct1 := ciphertext1
	ct2 := ciphertext2
	scaleFactor := ct1.ScaleFactor

	if ct1.ScaleFactor > ct2.ScaleFactor {
		diff := ct1.ScaleFactor - ct2.ScaleFactor
		newCoeffs := make([]*pbc.Element, len(ct2.Coefficients)+diff)

		var i int
		for i = 0; i < len(ct2.Coefficients); i++ {
			newCoeffs[i] = ct2.Coefficients[i]
		}

		for ; i < len(ct2.Coefficients)+diff; i++ {
			newCoeffs[i] = pk.encryptZero()
		}

		ct2.Coefficients = newCoeffs

	} else if ct2.ScaleFactor > ct1.ScaleFactor {
		// flip the ciphertexts
		return pk.EAddL2(ciphertext2, ciphertext1)
	}

	degree := int(math.Max(float64(len(ct1.Coefficients)), float64(len(ct2.Coefficients))))
	result := make([]*pbc.Element, degree)

	for i := degree - 1; i >= 0; i-- {

		if i >= len(ct2.Coefficients) {
			result[i] = ct1.Coefficients[i]
			continue
		}

		if i >= len(ct1.Coefficients) {
			result[i] = ct2.Coefficients[i]
			continue
		}

		result[i] = pk.eAddL2(ct1.Coefficients[i], ct2.Coefficients[i])
	}

	return &Ciphertext{result, scaleFactor}
}

func (pk *PublicKey) eAddL2(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Mul(coeff1, coeff2)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	return result.Mul(result, pair)
}

// EMultC multiplies a level 1 (non-multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC(ct *Ciphertext, constant float64) *Ciphertext {

	constPoly := NewPlaintext(constant, pk.PolyBase)
	degree := len(ct.Coefficients) + len(constPoly.Coefficients)
	result := make([]*pbc.Element, degree)

	zero := pk.G1.NewFieldElement()
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := 0; i < len(ct.Coefficients); i++ {
		index := i
		for k := 0; k < len(constPoly.Coefficients); k++ {

			coeff := pk.G1.NewFieldElement()
			coeff.MulBig(ct.Coefficients[i], big.NewInt(constPoly.Coefficients[k]))

			r := newCryptoRandom(pk.N)
			q := pk.G1.NewFieldElement()
			q.MulBig(pk.Q, r)
			coeff.Mul(coeff, q)

			if !result[index].Equals(zero) {
				result[index] = pk.eAdd(result[index], coeff)
			} else {
				result[index] = coeff
			}

			index++
		}
	}

	// encrypt the padding zero coefficients
	for i := 0; i < degree; i++ {
		if result[i].Equals(zero) {
			result[i] = pk.encryptZero()
		}
	}

	return &Ciphertext{result, ct.ScaleFactor + constPoly.ScaleFactor}
}

// EMultCL2 multiplies a level 2 (multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultCL2(ct *Ciphertext, constant float64) *Ciphertext {

	constPoly := NewPlaintext(constant, pk.PolyBase)
	degree := len(ct.Coefficients) + len(constPoly.Coefficients)
	result := make([]*pbc.Element, degree)

	zero := pk.Pairing.NewGT().NewFieldElement()
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := 0; i < len(ct.Coefficients); i++ {
		index := i
		for k := 0; k < len(constPoly.Coefficients); k++ {

			coeff := pk.Pairing.NewGT().NewFieldElement()
			coeff.MulBig(ct.Coefficients[i], big.NewInt(constPoly.Coefficients[k]))
			r := newCryptoRandom(pk.N)
			pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
			pair.PowBig(pair, r)
			coeff.Mul(coeff, pair)

			if !result[index].Equals(zero) {
				result[index] = pk.eAddL2(result[index], coeff)
			} else {
				result[index] = coeff
			}

			index++
		}
	}

	// encrypt the padding zero coefficients
	for i := 0; i < degree; i++ {
		if result[i].Equals(zero) {
			result[i] = pk.encryptZeroL2()
		}
	}

	return &Ciphertext{result, ct.ScaleFactor + constPoly.ScaleFactor}
}

// EMult multiplies two level 1 (non-multiplied) ciphertext together and returns the result
func (pk *PublicKey) EMult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	degree := len(ct1.Coefficients) + len(ct2.Coefficients)
	result := make([]*pbc.Element, degree)

	zero := pk.Pairing.NewGT().NewFieldElement()
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := 0; i < len(ct1.Coefficients); i++ {
		index := i
		for k := 0; k < len(ct2.Coefficients); k++ {

			coeff := pk.Pairing.NewGT().NewFieldElement()
			coeff.Pair(ct1.Coefficients[i], ct2.Coefficients[k])

			r := newCryptoRandom(pk.N)
			pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
			pair.PowBig(pair, r)

			coeff.Mul(coeff, pair)

			if !result[index].Equals(zero) {
				result[index] = pk.eAddL2(result[index], coeff)
			} else {
				result[index] = coeff
			}

			index++
		}
	}

	// encrypt the padding zero coefficients
	for i := 0; i < degree; i++ {
		if result[i].Equals(zero) {
			result[i] = pk.encryptZeroL2()
		}
	}

	return &Ciphertext{result, ct1.ScaleFactor + ct2.ScaleFactor}
}

func (pk *PublicKey) encryptZero() *pbc.Element {
	r := newCryptoRandom(pk.N)

	G := pk.G1.NewFieldElement()
	H := pk.G1.NewFieldElement()

	G.PowBig(pk.P, big.NewInt(0))
	H.PowBig(pk.Q, r)

	C := pk.G1.NewFieldElement()
	C.Mul(G, H)

	return C
}

func (pk *PublicKey) encryptZeroL2() *pbc.Element {

	zero := pk.encryptZero()

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Pair(zero, zero)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	result.Mul(result, pair)

	return result
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

	str := ""
	for _, coeff := range c.Coefficients {
		str += coeff.X().String() + "\n"
	}

	return str
}
