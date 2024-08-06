package party

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
	// Time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	Time time.Time

	// used as buffer for messages received before starting signing.
	// will be consumed once signing starts.
	MessageBuffer []tss.ParsedMessage

	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	LocalParty tss.Party
	sync.Once
	Mtx sync.Mutex
}

// SigningHandler handles all signers in the FullParty.
// The proper way to get a signer is to call getSignerOrCacheMessage, or getOrCreateSingleSigner.
// the former is used when we receive a request to sign, thus the signleSigner should have a LocalParty instance to process messages.
// the latter is used when we receive a message, but we might not YET be authorized to sign.
type SigningHandler struct {
	Mtx sync.Mutex

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

	errorChannel           chan<- *tss.Error
	OutChan                chan tss.Message
	signatureOutputChannel chan *common.SignatureData
	MaxTTl                 time.Duration
}

func (p *Impl) cleanupWorker() {
	for {
		select {
		case <-p.ctx.Done():
			return

		case <-time.After(p.MaxTTl):
			p.SigningHandler.cleanup(p.MaxTTl)
		}
	}
}
func (s *SigningHandler) cleanup(maxTTL time.Duration) {
	nmap := make(map[string]*SingleSigner)
	s.Mtx.Lock()
	defer s.Mtx.Unlock()

	currentTime := time.Now()
	for digest, signer := range s.DigestToSigner {
		if currentTime.Sub(signer.Time) > maxTTL {
			continue
		}

		nmap[digest] = signer
	}

	s.DigestToSigner = nmap
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

	go p.cleanupWorker()
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
		return errors.New("no key to sign with")
	}

	signer, err := p.getOrCreateSingleSigner(digest, secrets)
	if err != nil {
		return err
	}

	signer.Mtx.Lock()
	defer signer.Mtx.Unlock()

	if len(signer.MessageBuffer) > 0 {
		for _, message := range signer.MessageBuffer {
			ok, err := signer.LocalParty.Update(message)
			if !ok {
				p.reportError(err)
			}
		}

		signer.MessageBuffer = nil
	}

	return nil
}

func (s *SigningHandler) getSignerOrCacheMessage(message tss.ParsedMessage) (*SingleSigner, *tss.Error) {
	s.Mtx.Lock()

	signer, ok := s.DigestToSigner[string(message.WireMsg().GetDigest())]
	if !ok {

		s.DigestToSigner[string(message.WireMsg().GetDigest())] = &SingleSigner{
			Time:          time.Now(),
			MessageBuffer: []tss.ParsedMessage{message},
			LocalParty:    nil, // cannot be set int this method. Must be set in getOrCreateSingleSigner
			Once:          sync.Once{},
			Mtx:           sync.Mutex{},
		}

		s.Mtx.Unlock()

		return nil, nil
	}
	s.Mtx.Unlock()

	signer.Mtx.Lock()
	// haven't been requested to sign this digest yet: cache the message, and return a nil signer.
	if signer.LocalParty == nil {
		signer.MessageBuffer = append(signer.MessageBuffer, message)
		signer.Mtx.Unlock()

		return nil, nil
	}
	signer.Mtx.Unlock()

	// signer.LocalParty is not nil: signing is permitted.
	// We ensure we don't return an uninitialized localParty, by calling Start() if it hasn't been called yet.
	var e *tss.Error
	signer.Once.Do(func() { e = signer.LocalParty.Start() })

	if e != nil && e.Cause() != nil {
		return nil, e
	}

	return signer, nil
}

func (p *Impl) getOrCreateSingleSigner(digest Digest, secrets *keygen.LocalPartySaveData) (*SingleSigner, error) {
	p.SigningHandler.Mtx.Lock()
	signer, ok := p.SigningHandler.DigestToSigner[string(digest[:])]
	if !ok {
		signer = &SingleSigner{Time: time.Now()}
		p.SigningHandler.DigestToSigner[string(digest[:])] = signer
	}
	p.SigningHandler.Mtx.Unlock()

	signer.Mtx.Lock()
	if signer.LocalParty == nil {
		signer.LocalParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			p.Parameters,
			*secrets,
			p.OutChan,
			p.signatureOutputChannel,
		)
	}
	signer.Mtx.Unlock()

	var e error
	signer.Once.Do(func() {
		if err := signer.LocalParty.Start(); err != nil && err.Cause() != nil {
			e = err
		}
	})

	return signer, e
}

func (p *Impl) Update(message tss.ParsedMessage) error {
	select {
	case p.incomingMessagesChannel <- message:
		return nil
	case <-p.ctx.Done():
		return errors.New("worker stopped")
	}
}

func (p *Impl) handleIncomingSigningMessage(message tss.ParsedMessage) {
	signer, err := p.SigningHandler.getSignerOrCacheMessage(message)
	if err != nil {
		p.reportError(err)
		return
	}

	if signer == nil {
		// (SAFETY) To ensure messages aren't signed blindly because some rouge
		// Party started signing without a valid reason, this Party will only sign if it knows of the digest.
		return
	}

	ok, err := signer.LocalParty.Update(message)
	if !ok {
		p.reportError(err)
	}
}

func (p *Impl) reportError(newError *tss.Error) {
	select {
	case p.errorChannel <- newError:
	case <-p.ctx.Done():
	default:
		// no one is waiting on error reporting channel/ no buffer.
	}
}
