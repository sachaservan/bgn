package bgn

import (
	"fmt"
	"math"
	"math/big"
)

var degreeSumTable []*big.Int
var degreeTable []*big.Int
var computedBase int

const degreeBound = 128 // note: 3^64 > Int64 hence this is a generous upper bound

// Plaintext struct holds data related to the polynomial encoded plaintext
type Plaintext struct {
	Coefficients []int64 // coefficients in the plaintext or ciphertext poly
	Degree       int
	Base         int
	ScaleFactor  int
}

// NewUnbalancedPlaintext generates an unbalanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func NewUnbalancedPlaintext(m *big.Float, b int) *Plaintext {

	if degreeTable == nil || computedBase != b {
		computedBase = b
		degreeTable, degreeSumTable = computeDegreeTable(big.NewInt(int64(b)), degreeBound)
	}

	mFloat, _ := m.Float64()
	// m is a rational number, encode it rationally
	if math.Remainder(mFloat, 1.0) != 0.0 {
		mFloat, _ := m.Float64()
		numerator, scaleFactor := rationalize(mFloat-math.Floor(mFloat), b)
		mInt := big.NewInt(0)
		m.Int(mInt)
		mInt.Add(mInt, big.NewInt(numerator))

		coeffs, degree := unbalancedEncode(mInt, b, degreeTable, degreeSumTable)
		return &Plaintext{coeffs, degree, b, scaleFactor}
	}

	// m is an big.Int
	mInt := big.NewInt(0)
	m.Int(mInt)
	coeffs, degree := unbalancedEncode(mInt, b, degreeTable, degreeSumTable)
	return &Plaintext{coeffs, degree, b, 0}
}

// NewPlaintext generates an balanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func NewPlaintext(m *big.Float, b int) *Plaintext {

	if degreeTable == nil || computedBase != b {
		degreeTable, degreeSumTable = computeDegreeTable(big.NewInt(int64(b)), degreeBound)
	}

	mFloat, _ := m.Float64()

	// m is a rational number, encode it rationally
	if math.Remainder(mFloat, 1.0) != 0.0 {

		numerator, scaleFactor := rationalize(mFloat-math.Floor(mFloat), b)
		mInt := big.NewInt(0)
		m.Int(mInt)
		mInt.Add(mInt, big.NewInt(numerator))

		// fmt.Printf("Encoded rational approximation to %f is (%d/%d^%d) = %f\n", m, numerator, b, scaleFactor, float64(numerator)/math.Pow(float64(b), float64(scaleFactor)))
		coeffs, degree := balancedEncode(mInt, b, degreeTable, degreeSumTable)
		return &Plaintext{coeffs, degree, b, scaleFactor}
	}

	//m is an int
	mInt := big.NewInt(0)
	m.Int(mInt)
	coeffs, degree := balancedEncode(mInt, b, degreeTable, degreeSumTable)
	return &Plaintext{coeffs, degree, b, 0}
}

func computeDegreeTable(base *big.Int, bound int) ([]*big.Int, []*big.Int) {

	degreeTable := make([]*big.Int, bound)
	degreeSumTable := make([]*big.Int, bound)

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

	return degreeTable, degreeSumTable
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

func unbalancedEncode(target *big.Int, base int, degrees []*big.Int, sumDegrees []*big.Int) ([]int64, int) {

	// special case
	if target.Cmp(big.NewInt(0)) == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return coefficients, 1
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
			return coefficients[:bound+1], bound + 1
		}

		target.Sub(target, value)
	}
}

func balancedEncode(target *big.Int, base int, degrees []*big.Int, sumDegrees []*big.Int) ([]int64, int) {

	// special case
	if target.Int64() == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return coefficients, 1
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

			return coefficients[:bound+1], bound + 1
		}

		if degrees[index].Cmp(target) >= 1 {
			nextNegative = !nextNegative
			target.Sub(degrees[index], target)
		} else {
			target.Sub(target, degrees[index])
		}
	}
}

func reverse(numbers []int64) []int64 {
	for i := 0; i < len(numbers)/2; i++ {
		j := len(numbers) - i - 1
		numbers[i], numbers[j] = numbers[j], numbers[i]
	}
	return numbers
}

// rationalize float x as a base b encoded polynomial and a scalefactor
func rationalize(x float64, base int) (int64, int) {

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

	err := 0.00001 // min float 64
	qmin := x - err
	qmax := x + err

	for {
		// TODO: make more elegant, brute force right now...
		denom := math.Pow(float64(base), pow)
		rat := num / denom
		if rat <= qmax && rat >= qmin {
			fmt.Printf("pow is %d\n", int(pow))
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
func (p *Plaintext) PolyEval() *big.Float {

	acc := big.NewFloat(0.0)
	x := big.NewFloat(float64(p.Base))

	for i := p.Degree - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, big.NewFloat(float64(p.Coefficients[i])))
	}

	if p.ScaleFactor != 0 {
		scale := big.NewInt(0).Exp(big.NewInt(int64(p.Base)), big.NewInt(int64(p.ScaleFactor)), nil)
		denom := big.NewFloat(0.0).SetInt(scale)
		res := acc.Quo(acc, denom)

		return res
	}

	return acc
}

func checkOverflow(x *big.Int) bool {
	max := big.NewInt(9223372036854775807) // max value of int64
	return x.Cmp(max) > 0
}

func (p *Plaintext) String() string {

	/* un-comment below for polynomial representation of the plaintext value */

	// s := ""
	// for i := 0; i < p.Degree; i++ {

	// 	s += fmt.Sprintf("%d*%d^%d", p.Coefficients[i], p.Base, i)

	// 	if i < p.Degree-1 {
	// 		s += " + "
	// 	}
	// }

	// return fmt.Sprintf("%s [%s] {%d}", p.PolyEval().String(), s, p.ScaleFactor)

	return fmt.Sprintf("%s", p.PolyEval().String())
}
