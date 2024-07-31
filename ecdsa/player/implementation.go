package player

import (
	"crypto/ecdsa"
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	utils "github.com/bnb-chain/tss-lib/v2/ecdsa/ethereum"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type KeygenHandler struct {
	LocalParty  tss.Party
	StoragePath string
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

	incomingMessagesChannel chan tss.Message

	IdToPIDmapping map[string]*tss.PartyID
}

func (k *KeygenHandler) setup(outChan tss.Message) {
	// either create a new localParty, or load from storage

}

func (p *Impl) messageHandler() {
	// TODO implement me
}

func (p *Impl) Start(outChannel chan tss.Message, signatureOutputChannel chan utils.EthContractSignature, errChannel chan tss.Error) {
	// TODO: spin up msg handlers.

	for i := 0; i < runtime.NumCPU(); i++ {
		go p.messageHandler()
	}

	p.KeygenHandler.setup(outChannel)
	// TODO implement me

	panic("implement me")
}

func (p *Impl) Stop() {
	// TODO implement me
	panic("implement me")
}

func (p *Impl) AsyncRequestNewSignature(digest Digest) error {
	// TODO implement me
	panic("implement me")
}

type protocolType int

const (
	unknownProtocolType protocolType = iota
	keygenProtocolType
	signingProtocolType
)

func (p *Impl) Update(message tss.ParsedMessage) error {
	switch findProtocolType(message) {
	case keygenProtocolType:
		return nil
	case signingProtocolType:
		return nil
	default:
		return errors.New("unknown protocol type")
	}
}

func findProtocolType(message tss.ParsedMessage) protocolType {
	fullMessageStructName := message.Type()
	if strings.Contains(fullMessageStructName, "keygen") {
		return keygenProtocolType
	}
	if strings.Contains(fullMessageStructName, "signing") {
		return signingProtocolType
	}
	return unknownProtocolType
}
