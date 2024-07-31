// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package player

import (
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	utils "github.com/bnb-chain/tss-lib/v2/ecdsa/ethereum"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type Parameters struct {
	// a path in the filesystem where data and files can be saved.
	SaveDirPath string

	AllPlayers []*tss.PartyID
	Self       *tss.PartyID

	Threshold int

	// P2P keys for generating signature all Players should recognise, more formally, this SecretKey should be tied
	// to the encoded public key in the Self field
	SecretKey *ecdsa.PrivateKey
}

type Digest [32]byte

type FullParty interface {
	// Start will set up the FullParty, and few sub-components (including few goroutines).
	// outChannel: will be used by this Party to request messages to be sent outside,
	//      these messages can be either broadcast requests (using protocol like reliable broadcast),
	//      or uni-cast requests (which should be encrypted)
	// signatureOutputChannel: will be used by this Party to output a signature
	//      which should be aggragated by a relay and constructed into a single ecdsa signature.
	Start(outChannel chan tss.Message, signatureOutputChannel chan utils.EthContractSignature, errChannel chan tss.Error)

	// Stop will Stop the FullPlarty
	Stop()

	// AsyncRequestNewSignature begins the signing protocol over the given digest.
	AsyncRequestNewSignature(Digest) error

	// Update will Update the FullParty with the ParsedMessage
	// while running the protocol.
	Update(tss.ParsedMessage) error
}

type Relay interface {
	ReconstructSignature(signatureData []*common.SignatureData) (utils.EthContractSignature, error)
}

type KeygenHandler struct {
	LocalParty tss.Party

	// communication channels
	Out               <-chan tss.Message
	ProtocolEndOutput <-chan *keygen.LocalPartySaveData

	SavedData *keygen.LocalPartySaveData
}

type SingleSigner struct {
	time.Time
	LocalParty tss.Party
}

type SigningHandler struct {
	Mtx sync.RWMutex

	DigestToSigner map[string]SingleSigner

	// shared by all signers
	OutChan          chan tss.Message
	SigPartReadyChan chan *common.SignatureData
}

type Impl struct {
	SecretKey      *ecdsa.PrivateKey
	PartyID        *tss.PartyID
	PeerContext    *tss.PeerContext
	Parameters     *tss.Parameters
	IdToPIDmapping map[string]*tss.PartyID

	KeygenHandler  *KeygenHandler
	SigningHandler *SigningHandler
}
