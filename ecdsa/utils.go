package ecdsa

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func AddVtoSig(v byte, mySig []byte) []byte {
	recID := v
	sig := append(mySig, []byte{recID}...)
	return sig
}

func CreateRecID(R *crypto.ECPoint, sumS *big.Int) byte {
	v := CreateV(R, sumS)
	// +4 because we work with compressed pk.
	sigv := 27 + v
	return sigv
}

var (
	secp256k1N     = ethcrypto.S256().Params().N
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

func IsBigS(s *big.Int) bool {
	return s.Cmp(secp256k1halfN) > 0
}

func FlipS(s *big.Int) *big.Int {
	v := big.Int{}
	v.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	return v.Sub(&v, s)
}

// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
func CreateV(R *crypto.ECPoint, sumS *big.Int) byte {
	v := byte(0)
	// R.X
	if R.X().Cmp(secp256k1N) > 0 {
		v = 2
	}

	if !IsEven(R.Y()) {
		v |= 1
	}

	// if isBigS(sumS) {
	// 	v ^= 1
	// }
	return v
}

func IsEven(nm *big.Int) bool {
	One := big.NewInt(1)
	tmp := One.And(One, nm)
	return tmp.Cmp(big.NewInt(0)) == 0
}
