package bgn

import (
	"math/big"

	"github.com/Nik-U/pbc"
)

// SecretKeyShare is a share of a secret key
type SecretKeyShare struct {
	Share *big.Int
}

type PartialDecrypt struct {
	Csk         *pbc.Element
	Gsk         *pbc.Element
	ScaleFactor int
}

// func (sk *SecretKeyShare) PartialDecrypt(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

// 	csk := pk.G1.NewFieldElement()
// 	gsk := pk.G1.NewFieldElement()

// 	csk.PowBig(ct.C, sk.Share)
// 	gsk.PowBig(pk.P, sk.Share)

// 	return &PartialDecrypt{csk, gsk, ct.Denominator, ct.IsRat}
// }

// func (sk *SecretKeyShare) PartialDecrypt2(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

// 	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
// 	gsk.PowBig(gsk, sk.Share)

// 	csk := ct.C.NewFieldElement()
// 	csk.PowBig(ct.C, sk.Share)

// 	return &PartialDecrypt{csk, gsk, ct.Denominator, ct.IsRat}
// }

// func CombinedShares(shares []*PartialDecrypt, pk *PublicKey) *Plaintext {

// 	csk := shares[0].Csk.NewFieldElement()
// 	gsk := shares[0].Gsk.NewFieldElement()

// 	csk.Set(shares[0].Csk)
// 	gsk.Set(shares[0].Gsk)

// 	for index, share := range shares {
// 		if index == 0 {
// 			continue
// 		}

// 		csk.Mul(csk, share.Csk)
// 		gsk.Mul(gsk, share.Gsk)
// 	}

// 	denominator := shares[0].Denominator
// 	isRat := shares[0].IsRat

// 	aux := gsk.NewFieldElement()
// 	aux.Set(gsk)

// 	// brute force compute the discrete log
// 	// TODO: use kangaroo!
// 	m := big.NewInt(1)

// 	for {
// 		if aux.Equals(csk) {
// 			break
// 		}

// 		aux = aux.Mul(aux, gsk)
// 		m = m.Add(m, big.NewInt(1))
// 	}

// 	return &Plaintext{m, denominator, isRat}
// }

// // NewMPKeyGen generates a new public key and n shares of a secret key
// func NewMPKeyGen(bits int, n int) (*PublicKey, []*SecretKeyShare, error) {

// 	// generate standard key pair
// 	var sk *SecretKey
// 	pk, sk, err := NewKeyGen(bits)

// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	// secret key shares
// 	var shares []*SecretKeyShare

// 	// max value of each share (no bigger than sk/n)
// 	max := big.NewInt(0).Div(sk.Key, big.NewInt(int64(n)))

// 	// sum of all the shares
// 	sum := big.NewInt(0)

// 	// compute shares
// 	for i := 0; i < n-1; i++ {
// 		// create new random share
// 		next := newCryptoRandom(max)
// 		shares = append(shares, &SecretKeyShare{next})
// 		sum.Add(sum, next)
// 	}

// 	// last share should be computed so as to
// 	// have all shares add up to sk
// 	last := sum.Sub(sk.Key, sum)
// 	shares = append(shares, &SecretKeyShare{last})

// 	return pk, shares, err
// }
