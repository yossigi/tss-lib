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

type singleSigner struct {
	// time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	time time.Time

	// used as buffer for messages received before starting signing.
	// will be consumed once signing starts.
	messageBuffer []tss.ParsedMessage

	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	localParty tss.Party
	once       sync.Once
	mtx        sync.Mutex
}

// signingHandler handles all signers in the FullParty.
// The proper way to get a signer is to call getSignerOrCacheMessage, or getOrCreateSingleSigner.
// the former is used when we receive a request to sign, thus the signleSigner should have a LocalParty instance to process messages.
// the latter is used when we receive a message, but we might not YET be authorized to sign.
type signingHandler struct {
	mtx sync.Mutex

	digestToSigner map[string]*singleSigner

	sigPartReadyChan chan *common.SignatureData
}

type Impl struct {
	ctx        context.Context
	cancelFunc context.CancelFunc

	partyID     *tss.PartyID
	peerContext *tss.PeerContext
	parameters  *tss.Parameters

	keygenHandler  *KeygenHandler
	signingHandler *signingHandler

	incomingMessagesChannel chan tss.ParsedMessage

	errorChannel           chan<- *tss.Error
	outChan                chan tss.Message
	signatureOutputChannel chan *common.SignatureData
	maxTTl                 time.Duration
}

func (p *Impl) cleanupWorker() {
	for {
		select {
		case <-p.ctx.Done():
			return

		case <-time.After(p.maxTTl):
			p.signingHandler.cleanup(p.maxTTl)
		}
	}
}
func (s *signingHandler) cleanup(maxTTL time.Duration) {
	nmap := make(map[string]*singleSigner)
	s.mtx.Lock()
	defer s.mtx.Unlock()

	currentTime := time.Now()
	for digest, signer := range s.digestToSigner {
		if currentTime.Sub(signer.time) > maxTTL {
			continue
		}

		nmap[digest] = signer
	}

	s.digestToSigner = nmap
}

func (p *Impl) getPublic() *ecdsa.PublicKey {
	if p.keygenHandler == nil {
		return nil
	}
	if p.keygenHandler.SavedData == nil {
		return nil
	}

	if p.keygenHandler.SavedData.ECDSAPub == nil {
		return nil
	}

	return p.keygenHandler.SavedData.ECDSAPub.ToECDSAPubKey()
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
				p.errorChannel <- tss.NewError(errors.New("received unknown message type"), "", 0, p.partyID, message.GetFrom())
			}
		case o := <-p.keygenHandler.ProtocolEndOutput:
			if err := p.keygenHandler.storeKeygenData(o); err != nil {
				p.errorChannel <- tss.NewError(err, "keygen data storing", 0, p.partyID, nil)
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
	p.outChan = outChannel

	for i := 0; i < runtime.NumCPU(); i++ {
		go p.worker()
	}

	go p.cleanupWorker()
	if err := p.keygenHandler.setup(outChannel, p.partyID); err != nil {
		p.Stop()
		return fmt.Errorf("keygen handler setup failed: %w", err)
	}

	return nil
}

func (p *Impl) Stop() {
	p.cancelFunc()
}

func (p *Impl) AsyncRequestNewSignature(digest Digest) error {
	secrets := p.keygenHandler.getSavedParams()
	if secrets == nil {
		return errors.New("no key to sign with")
	}

	signer, err := p.getOrCreateSingleSigner(digest, secrets)
	if err != nil {
		return err
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if len(signer.messageBuffer) > 0 {
		for _, message := range signer.messageBuffer {
			ok, err := signer.localParty.Update(message)
			if !ok {
				p.reportError(err)
			}
		}

		signer.messageBuffer = nil
	}

	return nil
}

func (s *signingHandler) getSignerOrCacheMessage(message tss.ParsedMessage) (*singleSigner, *tss.Error) {
	s.mtx.Lock()

	signer, ok := s.digestToSigner[string(message.WireMsg().GetDigest())]
	if !ok {

		s.digestToSigner[string(message.WireMsg().GetDigest())] = &singleSigner{
			time:          time.Now(),
			messageBuffer: []tss.ParsedMessage{message},
			localParty:    nil, // cannot be set int this method. Must be set in getOrCreateSingleSigner
			once:          sync.Once{},
			mtx:           sync.Mutex{},
		}

		s.mtx.Unlock()

		return nil, nil
	}
	s.mtx.Unlock()

	signer.mtx.Lock()
	// haven't been requested to sign this digest yet: cache the message, and return a nil signer.
	if signer.localParty == nil {
		signer.messageBuffer = append(signer.messageBuffer, message)
		signer.mtx.Unlock()

		return nil, nil
	}
	signer.mtx.Unlock()

	// signer.LocalParty is not nil: signing is permitted.
	// We ensure we don't return an uninitialized localParty, by calling Start() if it hasn't been called yet.
	var e *tss.Error
	signer.once.Do(func() { e = signer.localParty.Start() })

	if e != nil && e.Cause() != nil {
		return nil, e
	}

	return signer, nil
}

func (p *Impl) getOrCreateSingleSigner(digest Digest, secrets *keygen.LocalPartySaveData) (*singleSigner, error) {
	p.signingHandler.mtx.Lock()
	signer, ok := p.signingHandler.digestToSigner[string(digest[:])]
	if !ok {
		signer = &singleSigner{time: time.Now()}
		p.signingHandler.digestToSigner[string(digest[:])] = signer
	}
	p.signingHandler.mtx.Unlock()

	signer.mtx.Lock()
	if signer.localParty == nil {
		signer.localParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			p.parameters,
			*secrets,
			p.outChan,
			p.signatureOutputChannel,
		)
	}
	signer.mtx.Unlock()

	var e error
	signer.once.Do(func() {
		if err := signer.localParty.Start(); err != nil && err.Cause() != nil {
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
	signer, err := p.signingHandler.getSignerOrCacheMessage(message)
	if err != nil {
		p.reportError(err)
		return
	}

	if signer == nil {
		// (SAFETY) To ensure messages aren't signed blindly because some rouge
		// Party started signing without a valid reason, this Party will only sign if it knows of the digest.
		return
	}

	ok, err := signer.localParty.Update(message)
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
