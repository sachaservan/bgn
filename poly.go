package bgn

import (
	"math"
	"math/big"
	"sync"
)

// EncryptPoly encrupts a given plaintext (integer or rational) polynomial
// encoding under the public key pk
func (pk *PublicKey) EncryptPoly(pt *PolyPlaintext) *PolyCiphertext {

	encryptedCoefficients := make([]*Ciphertext, pt.Degree)

	for i := 0; i < pt.Degree; i++ {

		negative := (pt.Coefficients[i].Cmp(big.NewInt(0)) < 0)
		if negative {
			positive := new(big.Int).Mul(big.NewInt(-1), pt.Coefficients[i])
			coeff := positive
			encryptedCoefficients[i] = pk.Sub(pk.encryptZero(), pk.Encrypt(coeff))
		} else {
			coeff := pt.Coefficients[i]
			encryptedCoefficients[i] = pk.Encrypt(coeff)
		}
	}

	return &PolyCiphertext{encryptedCoefficients, pt.Degree, pt.ScaleFactor, false}
}

// DecryptPoly decrupts the PolyCiphertext and returns a PolyPlaintext
func (sk *SecretKey) DecryptPoly(ct *PolyCiphertext, pk *PublicKey) *PolyPlaintext {

	size := ct.Degree
	plaintextCoeffs := make([]*big.Int, size)

	for i := 0; i < ct.Degree; i++ {
		plaintextCoeffs[i], _ = sk.Decrypt(ct.Coefficients[i], pk)
	}

	return &PolyPlaintext{pk, plaintextCoeffs, size, ct.ScaleFactor}
}

// NegPoly returns the additive inverse of the level1 PolyCiphertext
func (pk *PublicKey) NegPoly(ct *PolyCiphertext) *PolyCiphertext {

	degree := ct.Degree
	result := make([]*Ciphertext, degree)

	for i := degree - 1; i >= 0; i-- {
		result[i] = pk.Sub(pk.encryptZero(), ct.Coefficients[i])
	}

	return &PolyCiphertext{result, ct.Degree, ct.ScaleFactor, ct.L2}
}

// EvalPoly homomorphically evaluates the polynomial on the base
func (pk *PublicKey) EvalPoly(ct *PolyCiphertext) *Ciphertext {
	acc := pk.EncryptDeterministic(big.NewInt(0))
	x := big.NewInt(int64(pk.PolyBase))

	for i := ct.Degree - 1; i >= 0; i-- {
		acc = pk.MultConst(acc, x)
		acc = pk.Add(acc, ct.Coefficients[i])
	}

	return acc
}

// MultConstPoly multiplies a PolyCiphertext with a plaintext constant
func (pk *PublicKey) MultConstPoly(ct *PolyCiphertext, constant *big.Float) *PolyCiphertext {

	isNegative := constant.Cmp(big.NewFloat(0.0)) < 0
	if isNegative {
		constant.Mul(constant, big.NewFloat(-1.0))
	}

	pk.mu.Lock()
	poly := pk.NewUnbalancedPlaintext(constant)
	pk.mu.Unlock()

	degree := ct.Degree + poly.Degree
	result := make([]*Ciphertext, degree)

	zero := pk.encryptZero()
	if ct.L2 {
		zero = pk.makeL2(zero)
	}

	// set all coefficients to zero
	for i := 0; i < degree; i++ {
		result[i] = zero
	}

	var mu sync.Mutex // mutex for addition
	var wg sync.WaitGroup
	for i := ct.Degree - 1; i >= 0; i-- {
		for k := poly.Degree - 1; k >= 0; k-- {
			wg.Add(1)
			index := i + k
			go func(index int, c1 *Ciphertext, c *big.Int) {
				defer wg.Done()
				coeff := zero.Copy()
				mu.Lock()
				coeff = pk.MultConst(c1, c)
				result[index] = pk.Add(result[index], coeff)
				mu.Unlock()
			}(index, ct.Coefficients[i], poly.Coefficients[k])
		}
	}

	wg.Wait()

	product := &PolyCiphertext{result, degree, ct.ScaleFactor + poly.ScaleFactor, ct.L2}

	if isNegative {
		return pk.NegPoly(product)
	}

	return product
}

// MultPoly multiplies two L1 PolyCiphertext together
func (pk *PublicKey) MultPoly(ct1 *PolyCiphertext, ct2 *PolyCiphertext) *PolyCiphertext {

	degree := ct1.Degree + ct2.Degree
	result := make([]*Ciphertext, degree)

	// encrypt the padding zero coefficients
	var wg sync.WaitGroup
	for i := 0; i < degree; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result[i] = pk.makeL2(pk.encryptZero())
		}(i)
	}
	wg.Wait()

	var mu sync.Mutex
	for i := ct1.Degree - 1; i >= 0; i-- {
		for k := ct2.Degree - 1; k >= 0; k-- {
			wg.Add(1)
			index := i + k
			go func(index int, coeff1, coeff2 *Ciphertext) {
				defer wg.Done()
				coeff := pk.Mult(coeff1, coeff2)
				mu.Lock()
				result[index] = pk.Add(result[index], coeff)
				mu.Unlock()
			}(index, ct1.Coefficients[i], ct2.Coefficients[k])
		}
	}
	wg.Wait()

	return &PolyCiphertext{result, degree, ct1.ScaleFactor + ct2.ScaleFactor, true}
}

// MakePolyL2 moves a given PolyCiphertext to the GT field
func (pk *PublicKey) MakePolyL2(ct *PolyCiphertext) *PolyCiphertext {

	one := pk.EncryptPoly(pk.NewPolyPlaintext(big.NewFloat(1.0)))
	return pk.MultPoly(one, ct)
}

// SubPoly subtracts PolyCiphertext ct2 from ct1 and returns the result
func (pk *PublicKey) SubPoly(ct1 *PolyCiphertext, ct2 *PolyCiphertext) *PolyCiphertext {
	return pk.AddPoly(ct1, pk.NegPoly(ct2))
}

// AddPoly adds two PolyCiphertexts together and returns the result
func (pk *PublicKey) AddPoly(pct1 *PolyCiphertext, pct2 *PolyCiphertext) *PolyCiphertext {

	if pct1.L2 || pct2.L2 {

		if !pct1.L2 {
			return pk.AddPoly(pk.MakePolyL2(pct1), pct2)
		}

		if !pct2.L2 {
			return pk.AddPoly(pct1, pk.MakePolyL2(pct2))
		}
	}

	ct1 := pct1.Copy()
	ct2 := pct2.Copy()
	ct1, ct2 = pk.alignPolyCiphertexts(ct1, ct2, false)

	degree := int(math.Max(float64(ct1.Degree), float64(ct2.Degree)))
	result := make([]*Ciphertext, degree)

	for i := degree - 1; i >= 0; i-- {

		if i >= ct2.Degree {
			result[i] = ct1.Coefficients[i]
			continue
		}

		if i >= ct1.Degree {
			result[i] = ct2.Coefficients[i]
			continue
		}

		result[i] = pk.Add(ct1.Coefficients[i], ct2.Coefficients[i])
	}

	return &PolyCiphertext{result, degree, ct1.ScaleFactor, ct1.L2}
}

func (pk *PublicKey) alignPolyCiphertexts(ct1 *PolyCiphertext, ct2 *PolyCiphertext, level2 bool) (*PolyCiphertext, *PolyCiphertext) {

	if ct1.ScaleFactor > ct2.ScaleFactor {
		diff := ct1.ScaleFactor - ct2.ScaleFactor

		ct2 = pk.MultConstPoly(ct2, big.NewFloat(math.Pow(float64(pk.FPScaleBase), float64(diff))))
		ct2.ScaleFactor = ct1.ScaleFactor

	} else if ct2.ScaleFactor > ct1.ScaleFactor {
		// flip the PolyCiphertexts
		return pk.alignPolyCiphertexts(ct2, ct1, level2)
	}

	return ct1, ct2
}
