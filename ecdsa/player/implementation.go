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
	SecretKey   *ecdsa.PrivateKey
	PartyID     *tss.PartyID
	PeerContext *tss.PeerContext
	Parameters  *tss.Parameters

	KeygenHandler  *KeygenHandler
	SigningHandler *SigningHandler

	IdToPIDmapping map[string]*tss.PartyID
}

func (i Impl) Start(outChannel chan tss.Message, signatureOutputChannel chan utils.EthContractSignature, errChannel chan tss.Error) {
	// TODO implement me
	panic("implement me")
}

func (i Impl) Stop() {
	// TODO implement me
	panic("implement me")
}

func (i Impl) AsyncRequestNewSignature(digest Digest) error {
	// TODO implement me
	panic("implement me")
}

func (i Impl) Update(message tss.ParsedMessage) error {
	// TODO implement me
	panic("implement me")
}
