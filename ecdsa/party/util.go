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
