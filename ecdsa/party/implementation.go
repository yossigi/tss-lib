package party

import (
	"bytes"
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

	"github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/ecdsa/keygen"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
	"golang.org/x/crypto/sha3"
)

type KeygenHandler struct {
	LocalParty  tss.Party
	StoragePath string
	// communication channels
	ProtocolEndOutput <-chan *keygen.LocalPartySaveData

	SavedData *keygen.LocalPartySaveData
}

type partyIdIndex int

type signerState int

const (
	notStarted signerState = iota
	started
	startedNotInCommittee
)

type singleSigner struct {
	// time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	time time.Time

	// used as buffer for messages received before starting signing.
	// will be consumed once signing starts.
	messageBuffer  map[partyIdIndex][]tss.ParsedMessage
	partyIdToIndex map[Digest]partyIdIndex
	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	localParty tss.Party
	once       sync.Once
	mtx        sync.Mutex

	// the state of the signer. can be one of { notStarted, started, startedNotInCommittee }.
	state signerState
}

// signingHandler handles all signers in the FullParty.
// The proper way to get a signer is to use getOrCreateSingleSigner method.
type signingHandler struct {
	mtx sync.Mutex

	digestToSigner map[string]*singleSigner

	sigPartReadyChan chan *common.SignatureData
}

// Impl handles multiple signers
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
	cryptoWorkChan         chan func()
	maxTTl                 time.Duration
	loadDistributionSeed   []byte
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
		if currentTime.Sub(signer.time) < maxTTL {
			nmap[digest] = signer
		}
	}

	s.digestToSigner = nmap
}

func (p *Impl) GetPublic() *ecdsa.PublicKey {
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

	p.initCryptopool()

	go p.cleanupWorker()

	if err := p.keygenHandler.setup(outChannel, p.partyID); err != nil {
		p.Stop()

		return fmt.Errorf("keygen handler setup failed: %w", err)
	}

	return nil
}
func (p *Impl) initCryptopool() {
	p.cryptoWorkChan = make(chan func(), runtime.NumCPU())
	p.parameters.Context = p.ctx
	p.parameters.AsyncWorkComputation = func(f func()) error {
		select {
		case p.cryptoWorkChan <- f:
			return nil
		case <-p.ctx.Done():
			return errors.New("context aborted")
		}
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go p.cryptoWorker()
	}
}

func (p *Impl) cryptoWorker() {
	for {
		select {
		case f := <-p.cryptoWorkChan:
			f()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Impl) Stop() {
	p.cancelFunc()
}

func (p *Impl) AsyncRequestNewSignature(digest Digest) error {
	signer, err := p.getStartedSigner(digest)
	if err != nil {
		return err
	}

	signer.consumeBuffer(p.reportError)

	return nil
}

func (signer *singleSigner) consumeBuffer(errReportFunc func(newError *tss.Error)) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if len(signer.messageBuffer) > 0 {
		for _, messages := range signer.messageBuffer {
			for _, message := range messages {

				ok, err := signer.feedLocalParty(message)
				if !ok {
					errReportFunc(err)
				}
			}
		}

		signer.messageBuffer = nil
	}

}

// The signer isn't necessarily allowed to sign. as a result, we might return a nil signer - to ensure
// we don't sign messages blindly.
func (p *Impl) getSignerOrCacheMessage(message tss.ParsedMessage) (*singleSigner, *tss.Error) {
	signer := p.signingHandler.getOrCreateSingleSigner(string(message.WireMsg().GetTrackingID()))

	shouldSign := signer.attemptToCacheIfShouldNotSign(message)
	if !shouldSign {
		return nil, nil
	}

	return signer, signer.ensureStarted()
}

func (p *Impl) getStartedSigner(digest Digest) (*singleSigner, error) {
	signer := p.signingHandler.getOrCreateSingleSigner(string(digest[:]))

	if err := p.tryStartSigning(digest, signer); err != nil {
		return nil, err
	}

	if err := signer.ensureStarted(); err != nil {
		return nil, err
	}

	return signer, nil
}

func (signer *singleSigner) ensureStarted() *tss.Error {
	var e *tss.Error

	signer.once.Do(func() {
		if err := signer.localParty.Start(); err != nil && err.Cause() != nil {
			e = err
		}
	})

	return e
}

// Since storing to cache is done strictly when this signer had not yet started to sign, this
// method will return a bool indicating whether it is allowed to sign.
func (signer *singleSigner) attemptToCacheIfShouldNotSign(message tss.ParsedMessage) (shouldSign bool) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	switch signer.state {
	case notStarted:
		pindex := partyIdIndex(message.GetFrom().Index)
		if len(signer.messageBuffer[pindex]) < maxStoragePerParty {
			signer.messageBuffer[pindex] = append(signer.messageBuffer[pindex], message)
		}

	case started:
		shouldSign = true

	case startedNotInCommittee:
		signer.messageBuffer = nil // ensuring no messages are stored.
	}

	return
}

func (signer *singleSigner) feedLocalParty(msg tss.ParsedMessage) (bool, *tss.Error) {
	index, ok := signer.partyIdToIndex[pidToDigest(msg.GetFrom().MessageWrapper_PartyID)]
	if !ok {
		return false, tss.NewTrackableError(fmt.Errorf("msg from non committee member"), "", -1, nil, msg.WireMsg().TrackingID, msg.GetFrom())
	}

	msg.GetFrom().Index = int(index)

	return signer.localParty.Update(msg)
}

func pidToDigest(pid *tss.MessageWrapper_PartyID) Digest {
	bf := bytes.NewBuffer(nil)
	bf.WriteString(pid.Id)
	bf.Write(pid.Key)
	return sha3.Sum256(bf.Bytes())
}

var ErrNotInSigningCommittee = errors.New("self not in signing committee")
var ErrNoSigningKey = errors.New("no key to sign with")

// tryStartSigning attempts to start the signing protocol for the given digest (set signer.localParty).
// It can fail if the party isn't in the signing committee, or if there's no key to sign with.
func (p *Impl) tryStartSigning(digest Digest, signer *singleSigner) error {
	secrets := p.keygenHandler.getSavedParams()
	if secrets == nil {
		return ErrNoSigningKey
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	switch signer.state {
	case started:
		return nil
	case startedNotInCommittee:
		return ErrNotInSigningCommittee

	case notStarted:
		randomnessSeed := append(p.loadDistributionSeed, digest[:]...)

		parties, err := shuffleParties(randomnessSeed, p.parameters.Parties().IDs())
		if err != nil {
			return err
		}

		parties = tss.SortPartyIDs(parties[:p.parameters.Threshold()+1])

		selfIdInCurrentCommittee := p.selfInSigningCommittee(parties)
		if selfIdInCurrentCommittee == nil {
			signer.state = startedNotInCommittee

			return ErrNotInSigningCommittee
		}

		for _, party := range parties {
			signer.partyIdToIndex[pidToDigest(party.MessageWrapper_PartyID)] = partyIdIndex(party.Index)
		}

		signer.localParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			digest[:],
			p.makeParams(parties, selfIdInCurrentCommittee),
			*secrets,
			p.outChan,
			p.signatureOutputChannel,
			DigestSize,
		)

		signer.state = started
	}

	return nil
}

// since the parties and committee are shuffled we need to create specialized parameters for the signing protocol.
func (p *Impl) makeParams(parties []*tss.PartyID, selfIdInCurrentCommittee *tss.PartyID) *tss.Parameters {
	prms := tss.NewParameters(tss.S256(), tss.NewPeerContext(parties), selfIdInCurrentCommittee, len(parties), p.parameters.Threshold())
	prms.Context = p.parameters.Context
	prms.AsyncWorkComputation = p.parameters.AsyncWorkComputation
	return prms
}

// getOrCreateSingleSigner returns the signer for the given digest, or creates a new one if it doesn't exist.
// the returned signer doesn't necessarily has a localParty instance, meaning it isn't allowed to sign yet.
func (s *signingHandler) getOrCreateSingleSigner(digestStr string) *singleSigner {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	signer, ok := s.digestToSigner[digestStr]
	if !ok {
		s.digestToSigner[digestStr] = &singleSigner{
			time:           time.Now(),
			messageBuffer:  map[partyIdIndex][]tss.ParsedMessage{},
			partyIdToIndex: map[Digest]partyIdIndex{},
			localParty:     nil,
			once:           sync.Once{},
			mtx:            sync.Mutex{},
			state:          notStarted,
		}

		signer = s.digestToSigner[digestStr]
	}

	return signer
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
	signer, err := p.getSignerOrCacheMessage(message)
	if err != nil {
		p.reportError(err)
		return
	}

	if signer == nil {
		// (SAFETY) To ensure messages aren't signed blindly because some rouge
		// Party started signing without a valid reason, this Party will only sign if it knows of the digest.
		return
	}

	ok, err := signer.feedLocalParty(message)
	if !ok {
		p.reportError(err)
	}
}

func (p *Impl) reportError(newError *tss.Error) {
	select {
	case p.errorChannel <- newError:
	case <-p.ctx.Done():
	default: // no one is waiting on error reporting channel/ no buffer.
	}
}

func (p *Impl) selfInSigningCommittee(parties []*tss.PartyID) *tss.PartyID {
	for _, party := range parties {
		// not checking moniker since it's for convenience only.
		if party.Id == p.partyID.Id && bytes.Equal(party.Key, p.partyID.Key) {
			return party
		}
	}

	return nil
}
