package player

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
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
	ctx        context.Context
	cancelFunc context.CancelFunc

	SecretKey   *ecdsa.PrivateKey
	PartyID     *tss.PartyID
	PeerContext *tss.PeerContext
	Parameters  *tss.Parameters

	KeygenHandler  *KeygenHandler
	SigningHandler *SigningHandler

	incomingMessagesChannel chan tss.ParsedMessage

	IdToPIDmapping         map[string]*tss.PartyID
	errorChannel           chan<- *tss.Error
	signatureOutputChannel chan *common.SignatureData
}

func (k *KeygenHandler) setup(outChan chan tss.Message, selfId *tss.PartyID) error {
	k.Out = outChan

	if k.SavedData != nil {
		return nil
	}

	content, err := os.ReadFile(k.keysFileName(selfId))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(content, &k.SavedData); err != nil {
		return err
	}

	// TODO: set up keygen.LocalParty, and run it.
	return nil
}

func (k *KeygenHandler) keysFileName(selfId *tss.PartyID) string {
	return path.Join(k.StoragePath, fmt.Sprintf("keygen_data_%d.json", selfId.Index))
}

func (k *KeygenHandler) storeKeygenData(toSave *keygen.LocalPartySaveData) error {
	k.SavedData = toSave
	content, err := json.Marshal(toSave)
	if err != nil {
		return err
	}

	return os.WriteFile(k.keysFileName(k.LocalParty.PartyID()), content, 0777)
}

const (
	unknownProtocolType protocolType = iota
	keygenProtocolType
	signingProtocolType
)

func findProtocolType(message tss.ParsedMessage) protocolType {
	fullMessageStructName := message.Type()
	if strings.Contains(fullMessageStructName, ".keygen.") {
		return keygenProtocolType
	}

	if strings.Contains(fullMessageStructName, ".signing.") {
		return signingProtocolType
	}
	return unknownProtocolType
}

// The worker serves as messages courier to all "localParty" instances.
func (p *Impl) worker() {
	for {
		select {
		case message := <-p.incomingMessagesChannel:
			switch findProtocolType(message) {
			case keygenProtocolType:
				fmt.Println("keygen protocol")
			case signingProtocolType:
				p.handleIncomingSigningMessage(message)
			default:
				p.errorChannel <- tss.NewError(errors.New("received unknown message type"), "", 0, p.PartyID, message.GetFrom())
			}
		case o := <-p.KeygenHandler.ProtocolEndOutput:
			if err := p.KeygenHandler.storeKeygenData(o); err != nil {
				p.errorChannel <- tss.NewError(err, "keygen data storing", 0, p.PartyID, nil)
			}
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Impl) Start(outChannel chan tss.Message, signatureOutputChannel chan *common.SignatureData, errChannel chan<- *tss.Error) error {
	if outChannel == nil || signatureOutputChannel == nil || errChannel == nil {
		return errors.New("nil channel passed to Start()")
	}

	p.errorChannel = errChannel
	p.signatureOutputChannel = signatureOutputChannel

	for i := 0; i < runtime.NumCPU(); i++ {
		go p.worker()
	}

	if err := p.KeygenHandler.setup(outChannel, p.PartyID); err != nil {
		p.Stop()
		return fmt.Errorf("keygen handler setup failed: %w", err)
	}

	return nil
}

func (p *Impl) Stop() {
	p.cancelFunc()
}

func (p *Impl) AsyncRequestNewSignature(digest Digest) error {
	panic("implement me")
}

type protocolType int

func (p *Impl) Update(message tss.ParsedMessage) error {
	return nil
}

func (p *Impl) handleIncomingSigningMessage(message tss.ParsedMessage) {
	panic("implement me")
}
