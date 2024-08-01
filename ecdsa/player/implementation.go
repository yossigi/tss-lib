package player

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type KeygenHandler struct {
	LocalParty  tss.Party
	StoragePath string
	// communication channels
	ProtocolEndOutput <-chan *keygen.LocalPartySaveData

	SavedData *keygen.LocalPartySaveData
}

type SingleSigner struct {
	time.Time
	LocalParty tss.Party
}

type SigningHandler struct {
	Mtx sync.RWMutex

	DigestToSigner map[string]*SingleSigner

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
	OutChan                chan tss.Message
	signatureOutputChannel chan *common.SignatureData
}

func (p *Impl) getPublic() *ecdsa.PublicKey {
	if p.KeygenHandler == nil {
		return nil
	}
	if p.KeygenHandler.SavedData == nil {
		return nil
	}

	if p.KeygenHandler.SavedData.ECDSAPub == nil {
		return nil
	}

	return p.KeygenHandler.SavedData.ECDSAPub.ToECDSAPubKey()
}

func (k *KeygenHandler) setup(outChan chan tss.Message, selfId *tss.PartyID) error {
	_ = outChan

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

func (k *KeygenHandler) getSavedParams() *keygen.LocalPartySaveData {
	return k.SavedData
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
	p.OutChan = outChannel

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
	secrets := p.KeygenHandler.getSavedParams()
	if secrets == nil {
		return errors.New("no keygen data to sign with")
	}

	// TODO: discuss faster setup with Yossi.
	p.SigningHandler.Mtx.Lock()
	defer p.SigningHandler.Mtx.Unlock()

	if _, ok := p.SigningHandler.DigestToSigner[string(digest[:])]; ok {
		return errors.New("already signed this digest")
	}

	singleSigner := &SingleSigner{
		Time: time.Now(),
		LocalParty: signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			p.Parameters,
			*secrets,
			p.OutChan,
			p.signatureOutputChannel, // TODO: consider using a new channel for each signer.
		),
	}
	if err := singleSigner.LocalParty.Start(); err != nil {
		return err
	}

	p.SigningHandler.DigestToSigner[string(digest[:])] = singleSigner
	return nil
}

type protocolType int

func (p *Impl) Update(message tss.ParsedMessage) error {
	tmp := message.WireMsg().GetDigest()
	_ = tmp
	// [41 191 112 33 2 14 168 157 189 145 239 82 2 43 90 101 75 85 237 65 140 158 122 186 113 239 59 67 165 22 105 242]
	panic("implement me")
	return nil
}

func (p *Impl) handleIncomingSigningMessage(message tss.ParsedMessage) {
	panic("implement me")
}
