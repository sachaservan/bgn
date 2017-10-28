package bgn

import (
	"fmt"
	"math"
	"math/big"
)

var degreeSumTable []int64
var degreeTable []int64
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
func NewUnbalancedPlaintext(m float64, b int, fpp int) *Plaintext {

	if degreeTable == nil || computedBase != b {
		computedBase = b
		degreeTable, degreeSumTable = computeDegreeTable(b, degreeBound)
	}

	// m is a rational number, encode it rationally
	if math.Remainder(m, 1.0) != 0.0 {
		numerator, scaleFactor := rationalize(m, b, fpp)
		coeffs, degree := unbalancedEncode(numerator, b, degreeTable, degreeSumTable)
		return &Plaintext{coeffs, degree, b, scaleFactor}
	}

	//m is an int
	coeffs, degree := unbalancedEncode(int64(m), b, degreeTable, degreeSumTable)
	return &Plaintext{coeffs, degree, b, 0}
}

// NewPlaintext generates an balanced base b encoded polynomial representation of m
// fpp is the starting floating point scale factor which determines the precision
func NewPlaintext(m float64, b int, fpp int) *Plaintext {

	if degreeTable == nil || computedBase != b {
		computedBase = b
		degreeTable, degreeSumTable = computeDegreeTable(b, degreeBound)
	}

	// m is a rational number, encode it rationally
	if math.Remainder(m, 1.0) != 0.0 {
		numerator, scaleFactor := rationalize(m, b, fpp)
		// fmt.Printf("Encoded rational approximation to %f is (%d/%d^%d) = %f\n", m, numerator, b, scaleFactor, float64(numerator)/math.Pow(float64(b), float64(scaleFactor)))
		coeffs, degree := balancedEncode(numerator, b, degreeTable, degreeSumTable)
		return &Plaintext{coeffs, degree, b, scaleFactor}
	}

	//m is an int
	coeffs, degree := balancedEncode(int64(m), b, degreeTable, degreeSumTable)
	return &Plaintext{coeffs, degree, b, 0}
}

func computeDegreeTable(base int, bound int) ([]int64, []int64) {

	degreeTable := make([]int64, bound)
	degreeSumTable := make([]int64, bound)

	sum := int64(1)
	degreeSumTable[0] = sum
	degreeTable[0] = 1

	for i := 1; i < bound; i++ {
		result := int64(math.Pow(float64(base), float64(i)))
		sum += result
		degreeTable[i] = result
		degreeSumTable[i] = sum
	}

	return degreeTable, degreeSumTable
}

// compute the closest degree to the target value
func degree(target int64, sums []int64, bound int, balanced bool) int {

	if target == 1 {
		return 0
	}

	if balanced {

		for i := 1; i <= bound; i++ {
			if degreeSumTable[i] >= target {
				return i
			}
		}

	} else {
		for i := 1; i <= bound; i++ {
			if degreeTable[i] > target {
				return i - 1
			}
		}
	}

	return -1
}

func unbalancedEncode(target int64, base int, degrees []int64, sumDegrees []int64) ([]int64, int) {

	// special case
	if target == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return coefficients, 1
	}

	if target < 0 {
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

		if 2*value <= target {
			value *= 2
			coefficients[index] = 2
		} else {
			coefficients[index] = 1
		}

		if value == target {
			return coefficients[:bound+1], bound + 1
		}

		target = target - value
	}
}

func balancedEncode(target int64, base int, degrees []int64, sumDegrees []int64) ([]int64, int) {

	// special case
	if target == 0 {
		coefficients := make([]int64, 1)
		coefficients[0] = 0
		return coefficients, 1
	}

	isNegative := target < 0
	if isNegative {
		target *= -1
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

		if degrees[index] == target {

			// make the poly negative
			if isNegative {
				for i := 0; i <= bound; i++ {
					coefficients[i] *= -1
				}
			}

			return coefficients[:bound+1], bound + 1
		}

		if target < degrees[index] {
			nextNegative = !nextNegative
			target = degrees[index] - target
		} else {
			target = target - degrees[index]
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
func rationalize(x float64, base int, precision int) (int64, int) {

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
	pow := float64(precision)

	err := 1.0 / (math.Pow(float64(base), pow+1))
	qmin := x - err
	qmax := x + err

	for {
		// TODO: make more elegant, brute force right now...
		denom := math.Pow(float64(base), pow)
		rat := num / denom
		if rat <= qmax && rat >= qmin {
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

	acc := big.NewFloat(0)
	x := big.NewFloat(float64(p.Base))

	for i := p.Degree - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, big.NewFloat(float64(p.Coefficients[i])))
	}

	if p.ScaleFactor != 0 {
		float, _ := acc.Float64()
		scale := math.Pow(float64(p.Base), float64(p.ScaleFactor))
		return big.NewFloat(float / scale)
	}

	return acc
}

func (p *Plaintext) String() string {

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
