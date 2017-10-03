package bgn

import (
	"math"
	"math/big"

	"github.com/Nik-U/pbc"
)

// SecretKeyShare is a share of a secret key
type SecretKeyShare struct {
	Share *big.Int
}

// multiply ct1*ct2 together in MPC
// Party 0 send everyone E(ct2)
// Party i generate/compute a_i, E(a_i) and E(ct2 a_i). Send E(a_i) and E(b a_i) to Party 0
// Party 0 computes E(ct1) – E(a), where E(a) is the sum of E(a_i)’s.
// All decrypt E(ct1-a)
// Party 0 computes E(ct2)*(ct1-a) + E(ct2*a) from E(ct2*a_i) it got in step 2.

type MPCEMultRequest struct {
	Ct *Ciphertext
}

type MPCEMultResponse struct {
	PartialTermA  *Ciphertext // E(a_i)
	PartialTermBA *Ciphertext // E(b*a_i)
}

type MPCEMultReceptacle struct {
	TermA  *Ciphertext
	TermBA *Ciphertext
}

type PartialDecrypt struct {
	Csks        []*pbc.Element
	Gsks        []*pbc.Element
	Degree      int
	ScaleFactor int
}

func NewMPCEmultRequest(ct *Ciphertext) *MPCEMultRequest {
	return &MPCEMultRequest{ct}
}

func (pk *PublicKey) RequestMPCMultiplication(request *MPCEMultRequest) *MPCEMultResponse {

	termA := math.Floor(math.Sqrt(float64(newCryptoRandom(big.NewInt(100)).Int64())))
	if newCryptoRandom(big.NewInt(1)).Cmp(big.NewInt(0)) == 0 {
		termA *= -1
	}

	termAPoly := NewPlaintext(termA, pk.PolyBase, pk.FPPrecision)
	termAEnc := pk.Encrypt(termAPoly)

	return &MPCEMultResponse{termAEnc, pk.EMultC(request.Ct, termA)}
}

func (sk *SecretKeyShare) PartialDecrypt(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	csks := make([]*pbc.Element, ct.Degree)
	gsks := make([]*pbc.Element, ct.Degree)

	for i, coeff := range ct.Coefficients {

		gsk := pk.G1.NewFieldElement()
		csk := pk.G1.NewFieldElement()
		gsks[i] = gsk.PowBig(pk.P, sk.Share)
		csks[i] = csk.PowBig(coeff, sk.Share)
	}

	return &PartialDecrypt{csks, gsks, ct.Degree, ct.ScaleFactor}
}

func (sk *SecretKeyShare) PartialDecryptL2(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	csks := make([]*pbc.Element, ct.Degree)
	gsks := make([]*pbc.Element, ct.Degree)

	for i, coeff := range ct.Coefficients {

		gsks[i] = pk.Pairing.NewGT().Pair(pk.P, pk.P)
		gsks[i].PowBig(gsks[i], sk.Share)

		csk := pk.Pairing.NewGT().NewFieldElement()
		csks[i] = csk.PowBig(coeff, sk.Share)
	}

	return &PartialDecrypt{csks, gsks, ct.Degree, ct.ScaleFactor}
}

func CombinedShares(shares []*PartialDecrypt, pk *PublicKey) *Plaintext {

	if len(shares) < 1 {
		panic("Number of shares to combine must be >= 1")
	}

	size := shares[0].Degree // assume all partial decrypts will have same number of coeffs
	csks := make([]*pbc.Element, size)
	gsks := make([]*pbc.Element, size)

	for i := 0; i < size; i++ {
		csks[i] = shares[0].Csks[i].NewFieldElement()
		gsks[i] = shares[0].Csks[i].NewFieldElement()
		csks[i].Set(shares[0].Csks[i])
		gsks[i].Set(shares[0].Gsks[i])
	}

	for index, share := range shares {

		if index == 0 {
			continue
		}

		for i := 0; i < share.Degree; i++ {
			csks[i].Mul(csks[i], share.Csks[i])
			gsks[i].Mul(gsks[i], share.Gsks[i])
		}
	}

	plaintextCoeffs := make([]int64, size)
	for i := 0; i < size; i++ {
		pt, err := pk.recoverMessageWithDL(gsks[i], csks[i])
		if err != nil {
			panic("not handled!")
		}
		plaintextCoeffs[i] = pt
	}

	return &Plaintext{plaintextCoeffs, size, pk.PolyBase, shares[0].ScaleFactor}

}

// NewMPCKeyGen generates a new public key and n shares of a secret key
func NewMPCKeyGen(numShares int, keyBits int, polyBase int, fpPrecision int) (*PublicKey, []*SecretKeyShare, error) {

	// generate standard key pair
	var sk *SecretKey
	pk, sk, err := NewKeyGen(keyBits, polyBase, fpPrecision)

	if err != nil {
		return nil, nil, err
	}

	// secret key shares
	var shares []*SecretKeyShare

	// max value of each share (no bigger than sk/n)
	max := big.NewInt(0).Div(sk.Key, big.NewInt(int64(numShares)))

	// sum of all the shares
	sum := big.NewInt(0)

	// compute shares
	for i := 0; i < numShares-1; i++ {
		// create new random share
		next := newCryptoRandom(max)
		shares = append(shares, &SecretKeyShare{next})
		sum.Add(sum, next)
	}

	// last share should be computed so as to
	// have all shares add up to sk
	last := sum.Sub(sk.Key, sum)
	shares = append(shares, &SecretKeyShare{last})

	return pk, shares, err
}
