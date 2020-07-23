package bgn

import (
	"math"
	"math/big"
)

var degreeSumTable []*big.Int
var degreeTable []*big.Int

const degreeBound = 128 // note: 3^64 > Int64 hence this is a generous upper bound

// PolyPlaintext is a polynomial encoded value
type PolyPlaintext struct {
	Pk           *PublicKey
	Coefficients []*big.Int // coefficients in the polynomial
	Degree       int        // degree of the polynomial
	ScaleFactor  int
}

// Plaintext struct holds data related to the polynomial encoded plaintext
type Plaintext struct {
	Pk    *PublicKey
	Value *big.Int
}

// NewPlaintext constructs a plaintext for the value m
func (pk *PublicKey) NewPlaintext(m *big.Int) *Plaintext {
	return &Plaintext{pk, m}
}

// NewUnbalancedPlaintext generates an unbalanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func (pk *PublicKey) NewUnbalancedPlaintext(m *big.Float) *PolyPlaintext {

	if degreeTable == nil {
		panic("Encoding tables not computed!")
	}

	mFloat, _ := m.Float64()
	// m is a rational number, encode it rationally
	if math.Remainder(mFloat, 1.0) != 0.0 {
		numerator, scaleFactor := rationalize(
			mFloat-math.Floor(mFloat),
			pk.PolyEncodingParams.FPScaleBase,
			pk.PolyEncodingParams.FPPrecision,
		)

		mInt := big.NewInt(0)
		m.Int(mInt)
		mInt.Mul(mInt, big.NewInt(int64(math.Pow(float64(pk.PolyEncodingParams.FPScaleBase), float64(scaleFactor)))))
		mInt.Add(mInt, big.NewInt(numerator))

		coeffs, degree := unbalancedEncode(mInt, pk.PolyEncodingParams.PolyBase, degreeTable, degreeSumTable)
		return &PolyPlaintext{pk, coeffs, degree, scaleFactor}
	}

	// m is a big.Int
	mInt := big.NewInt(0)
	m.Int(mInt)
	coeffs, degree := unbalancedEncode(mInt, pk.PolyEncodingParams.PolyBase, degreeTable, degreeSumTable)
	return &PolyPlaintext{pk, coeffs, degree, 0}
}

// NewPolyPlaintext generates an balanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func (pk *PublicKey) NewPolyPlaintext(m *big.Float) *PolyPlaintext {

	if degreeTable == nil {
		panic("Encoding tables not computed!")
	}

	mFloat, _ := m.Float64()

	// m is a rational number, encode it rationally
	if math.Remainder(mFloat, 1.0) != 0.0 {

		numerator, scaleFactor := rationalize(
			mFloat-math.Floor(mFloat),
			pk.PolyEncodingParams.FPScaleBase,
			pk.PolyEncodingParams.FPPrecision,
		)

		mInt := big.NewInt(0)
		m.Int(mInt)
		mInt.Mul(mInt, big.NewInt(int64(math.Pow(float64(pk.PolyEncodingParams.FPScaleBase), float64(scaleFactor)))))
		mInt.Add(mInt, big.NewInt(numerator))

		coeffs, degree := balancedEncode(mInt, pk.PolyEncodingParams.PolyBase, degreeTable, degreeSumTable)
		return &PolyPlaintext{pk, coeffs, degree, scaleFactor}
	}

	//m is an int
	mInt := big.NewInt(0)
	m.Int(mInt)
	coeffs, degree := balancedEncode(mInt, pk.PolyEncodingParams.PolyBase, degreeTable, degreeSumTable)
	return &PolyPlaintext{pk, coeffs, degree, 0}
}

func (pk *PublicKey) computeEncodingTable() {

	base := big.NewInt(int64(pk.PolyEncodingParams.PolyBase))
	bound := degreeBound

	degreeTable = make([]*big.Int, bound)
	degreeSumTable = make([]*big.Int, bound)

	sum := big.NewInt(1)
	degreeSumTable[0] = big.NewInt(1)
	degreeTable[0] = big.NewInt(1)

	for i := 1; i < bound; i++ {
		result := big.NewInt(0).Exp(base, big.NewInt(int64(i)), nil)
		sum.Add(sum, result)
		degreeTable[i] = result
		degreeSumTable[i] = big.NewInt(0)
		degreeSumTable[i].Set(sum)
	}
}

// compute the closest degree to the target value
func degree(target *big.Int, sums []*big.Int, bound int, balanced bool) int {

	if target.Int64() == 1 {
		return 0
	}

	if balanced {

		for i := 1; i <= bound; i++ {
			if degreeSumTable[i].Cmp(target) >= 0 {
				return i
			}
		}

	} else {
		for i := 1; i <= bound; i++ {
			if degreeTable[i].Cmp(target) >= 1 {
				return i - 1
			}
		}
	}

	return -1
}

func toBigIntArray(values []int64) []*big.Int {
	res := make([]*big.Int, len(values))
	for i, v := range values {
		res[i] = big.NewInt(v)
	}

	return res
}

func unbalancedEncode(target *big.Int, base int, degrees []*big.Int, sumDegrees []*big.Int) ([]*big.Int, int) {

	// special case
	if target.Cmp(big.NewInt(0)) == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return toBigIntArray(coefficients), 1
	}

	if target.Cmp(big.NewInt(0)) < 0 {
		panic("Negative encoding not supported")
	}

	if sumDegrees == nil {
		panic("No precomputed degree table!")
	}

	coefficients := make([]int64, degreeBound)
	bound := len(sumDegrees)
	lastDegree := degreeBound

	for {

		index := degree(target, sumDegrees, lastDegree, false)
		lastDegree = index + 1

		if bound == len(sumDegrees) {
			bound = index + 1
		}

		value := degrees[index]
		value2 := big.NewInt(0).Mul(degrees[index], big.NewInt(2))

		if value2.Cmp(target) <= 0 {
			value = value2
			coefficients[index] = 2
		} else {
			coefficients[index] = 1
		}

		if value.Cmp(target) == 0 {
			return toBigIntArray(coefficients[:bound+1]), bound + 1
		}

		target.Sub(target, value)
	}
}

func balancedEncode(target *big.Int, base int, degrees []*big.Int, sumDegrees []*big.Int) ([]*big.Int, int) {

	// special case
	if target.Int64() == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return toBigIntArray(coefficients), 1
	}

	isNegative := big.NewInt(0).Cmp(target) > 0
	if isNegative {
		target.Mul(target, big.NewInt(-1))
	}

	if sumDegrees == nil {
		panic("No precomputed degree table!")
	}

	coefficients := make([]int64, degreeBound)
	bound := len(sumDegrees)
	lastIndex := degreeBound
	nextNegative := false

	for {

		index := degree(target, sumDegrees, lastIndex, true)
		lastIndex = index

		if bound == len(sumDegrees) {
			bound = index
		}

		coefficients[index] = 1

		if nextNegative {
			coefficients[index] *= -1
		}

		if degrees[index].Cmp(target) == 0 {

			// make the poly negative
			if isNegative {
				for i := 0; i <= bound; i++ {
					coefficients[i] *= -1
				}
			}

			return toBigIntArray(coefficients[:bound+1]), bound + 1
		}

		if degrees[index].Cmp(target) >= 1 {
			nextNegative = !nextNegative
			target.Sub(degrees[index], target)
		} else {
			target.Sub(target, degrees[index])
		}
	}
}

// rationalize float x as a base b encoded polynomial and a scalefactor
func rationalize(x float64, base int, precision float64) (int64, int) {

	factor := math.Floor(x)

	x = 1.0 + math.Remainder(x, 1.0)
	if math.Abs(x) > 1.0 {
		x += 1.0
	}

	if x >= 0.0 {
		x -= float64(int(x))
	} else if x <= -0.0 {
		x += float64(int(x))
	}

	num := float64(1)
	pow := float64(1)

	qmin := x - precision
	qmax := x + precision

	for {
		// TODO: make more elegant, brute force right now...
		denom := math.Pow(float64(base), pow)
		rat := num / denom
		if rat <= qmax && rat >= qmin {

			// a hacky way to get the min ratio
			for (int(num) % base) == 0 {
				num = num / float64(base)
				pow--
			}
			denom := math.Pow(float64(base), pow)
			return int64(factor*denom + num), int(pow)
		}

		if num+1 >= denom {
			num = float64(1)
			pow++
		}

		num++
	}
}

// PolyEval evaluates a given polynomial using Horner's method
func (p *PolyPlaintext) PolyEval() *big.Float {

	acc := big.NewFloat(0.0)
	x := big.NewFloat(float64(p.Pk.PolyEncodingParams.PolyBase))

	for i := p.Degree - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, new(big.Float).SetInt(p.Coefficients[i]))
	}

	if p.ScaleFactor != 0 {
		scale := big.NewInt(0).Exp(
			big.NewInt(int64(p.Pk.PolyEncodingParams.FPScaleBase)), big.NewInt(int64(p.ScaleFactor)), nil)
		denom := big.NewFloat(0.0).SetInt(scale)
		res := acc.Quo(acc, denom)

		return res
	}

	return acc
}

func (p *PolyPlaintext) String() string {
	return p.PolyEval().String()
}
