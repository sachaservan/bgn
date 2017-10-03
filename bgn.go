package bgn

import (
	"crypto/rand"
	"errors"
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
	N           *big.Int     // product of two primes
	T           *big.Int     // message space T
	DT          *pbc.Element // encrypted q2-T
	Sk          *big.Int     // REMOVE! TODO: GET RID OF THIS
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

	T := big.NewInt(100000)

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
	l, err := parseLFromPBCParams(params)

	// choose random point P in G1
	P = G1.Rand()
	P.PowBig(P, l)

	// choose random Q in G1
	Q = G1.NewFieldElement()
	Q.PowBig(P, newCryptoRandom(N))
	Q.PowBig(Q, q2)

	// create public key with the generated groups
	pk := &PublicKey{pairing, G1, P, Q, N, T, nil, q2, polyBase, fpPrecision}

	s := big.NewInt(0).Sub(q2, T)
	DT := pk.encrypt(s)
	pk.DT = DT

	// create secret key
	sk := &SecretKey{q1, polyBase}

	return pk, sk, err
}

// Encrypt a given plaintext (integer or rational) with the public key pk
func (pk *PublicKey) Encrypt(pt *Plaintext) *Ciphertext {

	encryptedCoefficients := make([]*pbc.Element, pt.Degree)

	for i := 0; i < pt.Degree; i++ {

		negative := pt.Coefficients[i] < 0
		if negative {
			positive := -1 * pt.Coefficients[i]
			coeff := big.NewInt(positive)
			encryptedCoefficients[i] = pk.eSubElements(pk.encryptZero(), pk.encrypt(coeff))
		} else {
			coeff := big.NewInt(pt.Coefficients[i])
			encryptedCoefficients[i] = pk.encrypt(coeff)
		}
	}

	return &Ciphertext{encryptedCoefficients, pt.Degree, pt.ScaleFactor, false}
}

// AInv returns the additive inverse of the level1 ciphertext
func (pk *PublicKey) AInv(ct *Ciphertext) *Ciphertext {

	if ct.L2 {
		return pk.aInvL2(ct)
	}

	eT := pk.encrypt(pk.T)
	degree := ct.Degree
	result := make([]*pbc.Element, degree)

	for i := degree - 1; i >= 0; i-- {
		result[i] = pk.eSubElements(pk.eAddElements(pk.DT, eT), ct.Coefficients[i])
	}

	return &Ciphertext{result, ct.Degree, ct.ScaleFactor, ct.L2}
}

// EAdd adds two level 1 (non-multiplied) ciphertexts together and returns the result
func (pk *PublicKey) EAdd(ciphertext1 *Ciphertext, ciphertext2 *Ciphertext) *Ciphertext {

	if ciphertext1.L2 || ciphertext2.L2 {
		if !ciphertext1.L2 {
			return pk.eAddL2(pk.makeL2(ciphertext1), ciphertext2)
		}

		if !ciphertext2.L2 {
			return pk.eAddL2(ciphertext1, pk.makeL2(ciphertext2))
		}

		return pk.eAddL2(ciphertext1, ciphertext2)
	}

	ct1 := ciphertext1.Copy()
	ct2 := ciphertext2.Copy()
	ct1, ct2 = pk.alignCiphertexts(ct1, ct2, false)

	degree := int(math.Max(float64(ct1.Degree), float64(ct2.Degree)))
	result := make([]*pbc.Element, degree)

	for i := 0; i < degree; i++ {

		if ct2.Degree > i && ct1.Degree > i {
			result[i] = pk.eAddElements(ct1.Coefficients[i], ct2.Coefficients[i])
			continue
		}

		if i >= ct2.Degree {
			result[i] = ct1.Coefficients[i]
		}

		if i >= ct1.Degree {
			result[i] = ct2.Coefficients[i]
		}
	}

	return &Ciphertext{result, degree, ct1.ScaleFactor, ct1.L2}
}

// Decrypt the given ciphertext
func (sk *SecretKey) Decrypt(ct *Ciphertext, pk *PublicKey) *Plaintext {

	if ct.L2 {
		return sk.decryptL2(ct, pk)
	}

	size := ct.Degree
	plaintextCoeffs := make([]int64, size)

	for i := 0; i < ct.Degree; i++ {
		plaintextCoeffs[i] = sk.decryptElement(ct.Coefficients[i], pk, false)
	}

	return &Plaintext{plaintextCoeffs, size, pk.PolyBase, ct.ScaleFactor}
}

func (pk *PublicKey) aInvL2(ct *Ciphertext) *Ciphertext {

	eT := pk.encrypt(pk.T)

	degree := ct.Degree
	result := make([]*pbc.Element, degree)

	for i := degree - 1; i >= 0; i-- {
		result[i] = pk.eSubL2Elements(pk.toL2Element(pk.eAddElements(pk.DT, eT)), ct.Coefficients[i])
	}

	return &Ciphertext{result, ct.Degree, ct.ScaleFactor, ct.L2}
}

func (sk *SecretKey) decryptElement(el *pbc.Element, pk *PublicKey, failed bool) int64 {

	gsk := pk.G1.NewFieldElement()
	csk := pk.G1.NewFieldElement()
	gsk.PowBig(pk.P, sk.Key)
	csk.PowBig(el, sk.Key)

	pt, err := pk.recoverMessageWithDL(gsk, csk)
	if err != nil {
		if failed {
			panic("decryption failed twice. Message not recoverable.")
		}
		return sk.decryptElement(pk.eSubElements(el, pk.DT), pk, true)
	}
	return pt
}

func (sk *SecretKey) decryptElementL2(el *pbc.Element, pk *PublicKey, failed bool) int64 {

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk.PowBig(gsk, sk.Key)

	csk := el.NewFieldElement()
	csk.PowBig(el, sk.Key)

	pt, err := pk.recoverMessageWithDL(gsk, csk)
	if err != nil {
		if failed {
			panic("decryption failed twice. Message not recoverable.")
		}
		return sk.decryptElementL2(pk.eSubL2Elements(el, pk.toL2Element(pk.DT)), pk, true)
	}

	return pt
}

// DecryptL2 a level 2 (multiplied) ciphertext C using secret key sk
func (sk *SecretKey) decryptL2(ct *Ciphertext, pk *PublicKey) *Plaintext {

	size := ct.Degree
	plaintextCoeffs := make([]int64, size)

	for i := 0; i < ct.Degree; i++ {
		plaintextCoeffs[i] = sk.decryptElementL2(ct.Coefficients[i], pk, false)
	}

	return &Plaintext{plaintextCoeffs, ct.Degree, pk.PolyBase, ct.ScaleFactor}
}

// EAddL2 adds two level 2 (multiplied) ciphertexts together and returns the result
func (pk *PublicKey) eAddL2(ciphertext1 *Ciphertext, ciphertext2 *Ciphertext) *Ciphertext {

	ct1 := ciphertext1.Copy()
	ct2 := ciphertext2.Copy()
	ct1, ct2 = pk.alignCiphertexts(ct1, ct2, true)

	degree := int(math.Max(float64(ct1.Degree), float64(ct2.Degree)))
	result := make([]*pbc.Element, degree)

	for i := degree - 1; i >= 0; i-- {

		if i >= ct2.Degree {
			result[i] = ct1.Coefficients[i]
			continue
		}

		if i >= ct1.Degree {
			result[i] = ct2.Coefficients[i]
			continue
		}

		result[i] = pk.eAddL2Elements(ct1.Coefficients[i], ct2.Coefficients[i])
	}

	return &Ciphertext{result, degree, ct1.ScaleFactor, ct1.L2}
}

// EMultC multiplies a level 1 (non-multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) EMultC(ct *Ciphertext, constant float64) *Ciphertext {

	if ct.L2 {
		return pk.eMultCL2(ct, constant)
	}

	isNegative := constant < 0.0
	if isNegative {
		constant *= -1
	}

	poly := NewUnbalancedPlaintext(constant, pk.PolyBase, pk.FPPrecision)

	degree := ct.Degree + poly.Degree
	result := make([]*pbc.Element, degree)

	zero := pk.G1.NewFieldElement()

	// set all coefficients to zero
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := ct.Degree - 1; i >= 0; i-- {
		for k := poly.Degree - 1; k >= 0; k-- {
			index := i + k

			coeff := zero.NewFieldElement()
			coeff.PowBig(ct.Coefficients[i], big.NewInt(poly.Coefficients[k]))

			r := newCryptoRandom(pk.N)
			q := zero.NewFieldElement()
			q.MulBig(pk.Q, r)
			coeff.Mul(coeff, q)

			// don't bother adding if the coefficients are zero
			if result[index].Equals(zero) {
				result[index] = coeff
			} else {
				result[index] = pk.eAddElements(result[index], coeff)
			}
		}
	}

	product := &Ciphertext{result, degree, ct.ScaleFactor + poly.ScaleFactor, ct.L2}

	if isNegative {
		return pk.AInv(product)
	}

	return product
}

// EMultCL2 multiplies a level 2 (multiplied) ciphertext with a plaintext constant
// and returns the result
func (pk *PublicKey) eMultCL2(ct *Ciphertext, constant float64) *Ciphertext {

	isNegative := constant < 0.0
	if isNegative {
		constant *= -1
	}

	poly := NewUnbalancedPlaintext(constant, pk.PolyBase, pk.FPPrecision)

	degree := ct.Degree + poly.Degree
	result := make([]*pbc.Element, degree)

	zero := pk.Pairing.NewGT().NewFieldElement()

	// set all coefficients to zero
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := ct.Degree - 1; i >= 0; i-- {
		for k := poly.Degree - 1; k >= 0; k-- {
			index := i + k

			coeff := zero.NewFieldElement()
			coeff.PowBig(ct.Coefficients[i], big.NewInt(poly.Coefficients[k]))

			r := newCryptoRandom(pk.N)

			pair := zero.Pair(pk.Q, pk.Q)
			pair.PowBig(pair, r)

			coeff.Mul(coeff, pair)

			result[i] = coeff

			// don't bother adding if the coefficients are zero
			if result[index].Equals(zero) {
				result[index] = coeff
			} else {
				result[index] = pk.eAddL2Elements(result[index], coeff)
			}
		}
	}

	product := &Ciphertext{result, degree, ct.ScaleFactor + poly.ScaleFactor, ct.L2}

	if isNegative {
		return pk.AInv(product)
	}

	return product
}

// EMult multiplies two level 1 (non-multiplied) ciphertext together and returns the result
func (pk *PublicKey) EMult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	degree := ct1.Degree + ct2.Degree
	result := make([]*pbc.Element, degree)

	zero := pk.Pairing.NewGT().NewFieldElement()
	// encrypt the padding zero coefficients
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	for i := ct1.Degree - 1; i >= 0; i-- {
		for k := ct2.Degree - 1; k >= 0; k-- {
			index := i + k
			coeff := pk.Pairing.NewGT().NewFieldElement()
			coeff.Pair(ct1.Coefficients[i], ct2.Coefficients[k])

			r := newCryptoRandom(pk.N)
			pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
			pair.PowBig(pair, r)

			coeff.Mul(coeff, pair)

			if result[index] != zero {
				result[index] = pk.eAddL2Elements(result[index], coeff)
			} else {
				result[index] = coeff
			}
		}
	}

	return &Ciphertext{result, degree, ct1.ScaleFactor + ct2.ScaleFactor, true}
}

func (pk *PublicKey) toL2Element(el *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Pair(el, pk.encrypt(big.NewInt(1)))

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	return result.Mul(result, pair)
}

func (pk *PublicKey) makeL2(ct *Ciphertext) *Ciphertext {

	one := pk.Encrypt(NewPlaintext(1, pk.PolyBase, pk.FPPrecision))
	return pk.EMult(one, ct)
}

func (pk *PublicKey) encrypt(x *big.Int) *pbc.Element {

	r := newCryptoRandom(pk.N)

	G := pk.G1.NewFieldElement()
	H := pk.G1.NewFieldElement()

	G.PowBig(pk.P, x)
	H.PowBig(pk.Q, r)

	C := pk.G1.NewFieldElement()
	return C.Mul(G, H)
}

func (pk *PublicKey) recoverMessageWithDL(gsk *pbc.Element, csk *pbc.Element) (int64, error) {

	aux := gsk.NewFieldElement()
	aux.Set(gsk)

	zero := gsk.NewFieldElement()

	if zero.Equals(csk) {
		return 0, nil
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

		if m.Cmp(pk.T) >= 1 {
			return 0, errors.New("out of message space")
		}
	}

	threshold := big.NewInt(0).Div(pk.T, big.NewInt(2))
	if m.Cmp(threshold) >= 1 {
		m.Sub(m, pk.T)
	}

	return m.Int64(), nil
}

func (pk *PublicKey) eSubElements(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.Div(coeff1, coeff2)

	rand := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, rand)

	return result.Mul(result, h1)
}

func (pk *PublicKey) eSubL2Elements(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Div(coeff1, coeff2)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	return result.Mul(result, pair)
}

func (pk *PublicKey) eAddElements(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.G1.NewFieldElement()
	result.Mul(coeff1, coeff2)

	rand := newCryptoRandom(pk.N)
	h1 := pk.G1.NewFieldElement()
	h1.PowBig(pk.Q, rand)

	return result.Mul(result, h1)
}

func (pk *PublicKey) eAddL2Elements(coeff1 *pbc.Element, coeff2 *pbc.Element) *pbc.Element {

	result := pk.Pairing.NewGT().NewFieldElement()
	result.Mul(coeff1, coeff2)

	r := newCryptoRandom(pk.N)
	pair := pk.Pairing.NewGT().Pair(pk.Q, pk.Q)
	pair.PowBig(pair, r)

	return result.Mul(result, pair)
}

func (pk *PublicKey) alignCiphertexts(ct1 *Ciphertext, ct2 *Ciphertext, level2 bool) (*Ciphertext, *Ciphertext) {

	if ct1.ScaleFactor > ct2.ScaleFactor {
		diff := ct1.ScaleFactor - ct2.ScaleFactor
		newCoeffs := make([]*pbc.Element, ct2.Degree+diff)

		i := 0
		for ; i < diff; i++ {
			if level2 {
				newCoeffs[i] = pk.encryptZeroL2()
			} else {
				newCoeffs[i] = pk.encryptZero()
			}
		}

		for ; i < ct2.Degree+diff; i++ {
			newCoeffs[i] = ct2.Coefficients[i-diff]

		}

		ct2.Degree += diff
		ct2.Coefficients = newCoeffs
		ct2.ScaleFactor = ct1.ScaleFactor

	} else if ct2.ScaleFactor > ct1.ScaleFactor {
		// flip the ciphertexts
		return pk.alignCiphertexts(ct2, ct1, level2)
	}

	return ct1, ct2
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
func parseLFromPBCParams(params *pbc.Params) (*big.Int, error) {

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
		str += coeff.String() + "\n"
	}

	return str
}
