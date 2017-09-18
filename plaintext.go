package bgn

import (
	"fmt"
	"math"
	"math/big"

	"github.com/mjibson/go-dsp/fft"
)

var degreeSumTable []int64
var degreeTable []int64
var computedBase int

type Plaintext struct {
	Coefficients []int64 // coefficients in the plaintext or ciphertext poly
	Base         int
	ScaleFactor  int
}

func NewPlaintext(m float64, b int) *Plaintext {

	if degreeTable == nil || computedBase != b {
		computedBase = b
		degreeTable, degreeSumTable = computeDegreeTable(b, 64)
	}

	if math.Remainder(m, 1) != 0 {
		// m is a rational number
		numerator, scaleFactor := rationalize(m, float64(b), 10)
		res := float64(numerator) / math.Pow(float64(b), float64(scaleFactor))
		fmt.Printf("Encoded rational approximation to %f is (%d/%d^%d) = %f\n", m, numerator, b, scaleFactor, res)
		coeffs := encode(numerator, b, degreeTable, degreeSumTable)
		return &Plaintext{coeffs, b, scaleFactor}
	}

	// m is an int
	points := encode(int64(m), b, degreeTable, degreeSumTable)
	return &Plaintext{points, b, 0}
}

func pointForm(coeffs []int64) []complex128 {

	input := make([]complex128, len(coeffs))
	for i, coeff := range coeffs {
		input[i] = complex(float64(coeff), 0)
	}
	return fft.FFT(input)
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

func degree(target int64, sums []int64, bound int) int {

	if target == 1 {
		return 0
	}

	for i := 1; i <= bound; i++ {

		if sums[i] >= target {
			return i
		}
	}

	return -1
}

func encode(target int64, base int, degrees []int64, sumDegrees []int64) []int64 {

	if sumDegrees == nil {
		panic("No precomputed degree table!")
	}

	coefficients := make([]int64, 64)
	bound := len(sumDegrees)
	lastIndex := 64
	nextNegative := false

	for {

		index := degree(target, sumDegrees, lastIndex)
		lastIndex = index

		if bound == len(sumDegrees) {
			bound = index
		}

		coefficients[index] = 1

		if nextNegative {
			coefficients[index] *= -1
		}

		if degrees[index] == target {
			return coefficients[:bound+1]
		}

		if target < degrees[index] {
			nextNegative = !nextNegative
			target = degrees[index] - target
		} else {
			target = target - degrees[index]
		}
	}
}

func rationalize(x float64, base float64, pow float64) (int64, int) {

	factor := math.Floor(x)
	if x < 1 && x > -1 {
		factor = 1
	}

	x = 1.0 + math.Remainder(x, 1.0)
	if x >= 1.0 {
		x -= float64(int(x))
	} else if x <= -1 {
		x += float64(int(x))
	}

	num := float64(1)

	err := 1.0 / (math.Pow(base, pow) * 2)
	qmin := x - err
	qmax := x + err

	for {
		// TODO: make more elegant, brute force right now...

		denom := math.Pow(base, pow)
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

func (p *Plaintext) polyEval() *big.Float {

	acc := big.NewFloat(0)
	x := big.NewFloat(float64(p.Base))

	for i := len(p.Coefficients) - 1; i >= 0; i -= 1 {
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
	// for i := len(p.Coefficients) - 1; i >= 0; i-- {
	// 	if p.Coefficients[i] == 0 {
	// 		continue
	// 	}

	// 	s += fmt.Sprintf("%d*%d^%d", p.Coefficients[i], p.Base, i)

	// 	if i > 0 {
	// 		s += " + "
	// 	}
	// }

	return fmt.Sprintf("%s", p.polyEval().String())
}
