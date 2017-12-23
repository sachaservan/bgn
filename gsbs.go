package bgn

import (
	"errors"
	"math"
	"math/big"

	"github.com/Nik-U/pbc"
)

var tableG1 map[string]int64
var tableGT map[string]int64

func computeTableG1(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	tableG1 = make(map[string]int64, bound)

	for j := int64(0); j < bound; j++ {
		tableG1[aux.String()] = j
		aux.Mul(aux, gen)
	}
}

func computeTableGT(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	tableGT = make(map[string]int64, bound)

	for j := int64(0); j < bound; j++ {
		tableGT[aux.String()] = j
		aux.Mul(aux, gen)
	}
}

// obtain the discrete log in O(sqrt(T)) time using giant step baby step algorithm
func (pk *PublicKey) getDL(csk *pbc.Element, gsk *pbc.Element, l2 bool) (*big.Int, error) {

	// sqrt of the largest possible message
	bound := int64(math.Ceil(math.Sqrt(float64(pk.T.Int64()))))

	// pre-compute the tables for the giant steps
	//if l2 && tableGT == nil {
	computeTableGT(gsk, bound)
	//} else if tableG1 == nil {
	computeTableG1(gsk, bound)
	//}

	aux := csk.NewFieldElement()

	gamma := gsk.NewFieldElement()
	gamma.Set(gsk)
	gamma.PowBig(gamma, big.NewInt(0))

	aux.Set(csk)
	aux.Mul(aux, gamma)

	gamma.Set(gsk)
	gamma.PowBig(gamma, big.NewInt(bound))

	var val int64
	var ok bool

	for i := int64(0); i < bound; i++ {

		ok = false
		val = 0
		if l2 {
			val, ok = tableGT[aux.String()]
		} else {
			val, ok = tableG1[aux.String()]
		}

		if ok {
			return big.NewInt(i*bound + val + 1), nil
		}

		aux.Div(aux, gamma)
	}

	return nil, errors.New("cannot find discrete log; out of bounds")
}
