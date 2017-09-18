package bgn

import "github.com/Nik-U/pbc"

type Ciphertext struct {
	Coefficients []*pbc.Element // coefficients in the plaintext or ciphertext poly
	ScaleFactor  int
}
