package bgn

import "github.com/Nik-U/pbc"

type Ciphertext struct {
	Coefficients []*pbc.Element // coefficients in the plaintext or ciphertext poly
	Degree       int
	ScaleFactor  int
	L2           bool // whether ciphertext is level2
}

// Copy returns a copy of the given ciphertext
func (ct *Ciphertext) Copy() *Ciphertext {
	return &Ciphertext{ct.Coefficients, ct.Degree, ct.ScaleFactor, ct.L2}
}
