package bgn

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/Nik-U/pbc"
)

var tableG1 sync.Map
var tableGT sync.Map
var cache sync.Map
var usingCache = false

func computeTableG1(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	for j := int64(0); j < bound; j++ {
		tableG1.Store(aux.String(), j)
		aux.Mul(aux, gen)
	}
}

func computeTableGT(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	for j := int64(0); j < bound; j++ {
		tableGT.Store(aux.String(), j)
		aux.Mul(aux, gen)
	}
}

// ComputeDLCache builds a table of all possible discrete log values in
// the message space. Note: only use if using a relatively small value for T
func (pk *PublicKey) ComputeDLCache(gsk *pbc.Element) {

	aux := gsk.NewFieldElement()
	aux.Set(gsk)
	for i := 1; i <= int(pk.T.Int64()); i++ {

		res := big.NewInt(int64(i))
		cache.Store(aux.String(), res.Int64())
		aux.Mul(aux, gsk)
	}

	usingCache = true
}

// obtain the discrete log in O(sqrt(T)) time using giant step baby step algorithm
func (pk *PublicKey) getDL(csk *pbc.Element, gsk *pbc.Element, l2 bool) (*big.Int, error) {

	if usingCache {
		value, hit := cache.Load(csk.String())
		if hit {
			if v, ok := value.(int64); ok {
				fmt.Println("[DEBUG]: Discrete log cache hit.")
				return big.NewInt(v), nil
			}
		}
		fmt.Println("[DEBUG]: Discrete log cache miss.")
	}

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
	var found bool

	for i := int64(0); i < bound; i++ {

		found = false
		val = 0
		if l2 {
			value, hit := tableGT.Load(aux.String())
			if v, ok := value.(int64); ok {
				val = v
				found = hit
			}

		} else {
			value, hit := tableG1.Load(aux.String())
			if v, ok := value.(int64); ok {
				val = v
				found = hit
			}
		}

		if found {
			dl := big.NewInt(i*bound + val + 1)
			return dl, nil
		}

		aux.Div(aux, gamma)
	}

	return nil, errors.New("cannot find discrete log; out of bounds")
}
