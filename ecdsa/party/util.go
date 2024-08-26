package party

import (
	"crypto/rand"
	"math/big"

	"github.com/yossigi/tss-lib/v2/ecdsa/keygen"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
)

type protocolType int

const (
	unknownProtocolType protocolType = iota
	keygenProtocolType
	signingProtocolType
)

func findProtocolType(message tss.ParsedMessage) protocolType {
	switch message.Content().(type) {
	case *signing.SignRound1Message1, *signing.SignRound1Message2, *signing.SignRound2Message, *signing.SignRound3Message,
		*signing.SignRound4Message, *signing.SignRound5Message, *signing.SignRound6Message, *signing.SignRound7Message,
		*signing.SignRound8Message, *signing.SignRound9Message:
		return signingProtocolType
	case *keygen.KGRound1Message, *keygen.KGRound2Message1, *keygen.KGRound2Message2, *keygen.KGRound3Message:
		return keygenProtocolType
	default: // unrecognised message, just ignore!
		return unknownProtocolType
	}
}

func generateRandomShuffleOfIndices(n int) ([]int, error) {
	// generate a random shuffle of indices
	indices := make([]int, n)
	for i := 0; i < n; i++ {
		indices[i] = i
	}

	res := make([]int, 0, n)

	// shuffle
	for i := 0; i < n; i++ {
		bigpos, err := rand.Int(rand.Reader, big.NewInt(int64(len(indices))))
		if err != nil {
			return nil, err
		}

		pos := int(bigpos.Int64())
		elem := indices[pos]

		indices[pos] = indices[len(indices)-1]
		indices = indices[:len(indices)-1]

		res = append(res, elem)
	}

	return res, nil
}
