package postgres

import (
	"slices"

	webauthn "github.com/faustbrian/go-webauthn"
)

// Keep the original slice representation and order: protocol/request owners
// bind that exact profile, while nil retains the released ES256 default.
func validPasskeyAlgorithms(algorithms []webauthn.Algorithm) bool {
	if algorithms == nil {
		return true
	}
	if len(algorithms) == 0 || len(algorithms) > 2 {
		return false
	}
	for i, algorithm := range algorithms {
		if algorithm != webauthn.ES256 && algorithm != webauthn.EdDSA || slices.Contains(algorithms[:i], algorithm) {
			return false
		}
	}
	return true
}

func selectedPasskeyAlgorithm(algorithms []webauthn.Algorithm, algorithm int32) bool {
	if algorithms == nil {
		return algorithm == int32(webauthn.ES256)
	}
	return slices.Contains(algorithms, webauthn.Algorithm(algorithm))
}
