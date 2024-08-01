package party

import (
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
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

func findRound(message tss.ParsedMessage) int {
	switch message.Content().(type) {
	case *signing.SignRound1Message1, *signing.SignRound1Message2:
		return 1
	case *signing.SignRound2Message:
		return 2
	case *signing.SignRound3Message:
		return 3
	case *signing.SignRound4Message:
		return 4
	case *signing.SignRound5Message:
		return 5
	case *signing.SignRound6Message:
		return 6
	case *signing.SignRound7Message:
		return 7
	case *signing.SignRound8Message:
		return 8
	case *signing.SignRound9Message:
		return 9
	case *keygen.KGRound1Message:
		return 1
	case *keygen.KGRound2Message1, *keygen.KGRound2Message2:
		return 2
	case *keygen.KGRound3Message:
		return 3

	default: // unrecognised message, just ignore!
		return -1
	}
}
