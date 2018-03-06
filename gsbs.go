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
var cacheG1 sync.Map
var cacheGT sync.Map

var usingCache = false
var tablesComputed = false

func computeTableG1(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	for j := int64(0); j <= bound; j++ {
		tableG1.Store(aux.String(), j)
		aux.Mul(aux, gen)
	}
}

func computeTableGT(gen *pbc.Element, bound int64) {

	aux := gen.NewFieldElement()
	aux.Set(gen)

	for j := int64(0); j <= bound; j++ {
		tableGT.Store(aux.String(), j)
		aux.Mul(aux, gen)
	}
}

// PrecomputeTables builds the maps necessary
// for the giant step, baby step algorithm
func (pk *PublicKey) PrecomputeTables(genG1 *pbc.Element, genGT *pbc.Element) {

	// sqrt of the largest possible message
	bound := int64(math.Ceil(math.Sqrt(float64(pk.T.Int64())))) + 1

	// pre-compute the tables for the giant steps
	computeTableGT(genGT, bound)
	computeTableG1(genG1, bound)

	tablesComputed = true
}

// ComputeDLCache builds a table of all possible discrete log values in
// the message space. Note: only use if using a relatively small value for T
func (pk *PublicKey) ComputeDLCache(gskG1 *pbc.Element, gskGT *pbc.Element) {

	bound := pk.T.Int64()

	auxG1 := gskG1.NewFieldElement()
	cacheG1.Store(auxG1.String(), big.NewInt(0))
	auxG1.Set(gskG1)

	auxGT := gskGT.NewFieldElement()
	cacheGT.Store(auxGT.String(), big.NewInt(0))
	auxGT.Set(gskGT)

	for i := int64(1); i < bound; i++ {

		// G1 store
		cacheG1.Store(auxG1.String(), big.NewInt(i))
		// GT store
		cacheGT.Store(auxGT.String(), big.NewInt(i))

		auxG1 = auxG1.Mul(auxG1, gskG1)
		auxGT = auxGT.Mul(auxGT, gskGT)
	}

	usingCache = true
}

// obtain the discrete log in O(sqrt(T)) time using giant step baby step algorithm
func (pk *PublicKey) getDL(csk *pbc.Element, gsk *pbc.Element, l2 bool) (*big.Int, error) {

	if usingCache {

		if l2 {
			value, hit := cacheGT.Load(csk.String())
			if hit {
				if v, ok := value.(*big.Int); ok {
					return big.NewInt(0).Set(v), nil
				}
			}
		} else {
			value, hit := cacheG1.Load(csk.String())
			if hit {
				if v, ok := value.(*big.Int); ok {
					return big.NewInt(0).Set(v), nil
				}
			}
		}
		fmt.Println("[DEBUG]: Discrete log cache miss.")
	}

	if !tablesComputed {
		panic("DL tables not computed!")
	}

	bound := int64(math.Ceil(math.Sqrt(float64(pk.T.Int64()))))

	aux := csk.NewFieldElement()

	gamma := gsk.NewFieldElement()
	gamma.Set(gsk)
	gamma.MulBig(gamma, big.NewInt(0))

	aux.Set(csk)
	aux.Mul(aux, gamma)

	gamma.Set(gsk)
	gamma.MulBig(gamma, big.NewInt(bound))

	var val *big.Int
	var found bool

	for i := int64(0); i <= bound; i++ {

		found = false
		val = big.NewInt(0)

		if l2 {
			value, hit := tableGT.Load(aux.String())
			if v, ok := value.(int64); ok {
				val = big.NewInt(v)
				found = hit
			}

		} else {
			value, hit := tableG1.Load(aux.String())
			if v, ok := value.(int64); ok {
				val = big.NewInt(v)
				found = hit
			}
		}

		if found {
			dl := big.NewInt(i*bound + val.Int64() + 1)

			return dl, nil
		}
		aux.Div(aux, gamma)
	}

	return nil, errors.New("cannot find discrete log; out of bounds")
}
