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
	unset signerState = iota
	set
	notInCommittee
)

type singleSigner struct {
	// time represents the moment this signleSigner is created.
	// Given a timeout parameter, bookkeeping and cleanup will use this parameter.
	time   time.Time
	digest *Digest
	// This field might change during the lifetime of the signer.
	// every failed attempt to sign will change this field with a new value.
	trackingId []byte

	// messageBuffer stores messages that are received before the signer is received
	// the "Go" signal to start signing.
	// sorted to bins by partyID digest. (not including index)
	messageBuffer  map[Digest][]tss.ParsedMessage
	partyIdToIndex map[Digest]partyIdIndex
	comittee       []*tss.PartyID
	self           *tss.PartyID
	// nil if not started signing yet.
	// once a request to sign was received (via AsyncRequestNewSignature), this will be set,
	// and used.
	localParty tss.Party
	mtx        sync.Mutex

	// the state of the signer. can be one of { unset, set, started, notInCommittee }.
	state signerState
}

// signingHandler handles all signers in the FullParty.
// The proper way to get a signer is to use getOrCreateSingleSigner method.
type signingHandler struct {
	mtx sync.Mutex

	// might store the same signer multiple times: once for each tracking id.
	// the signer itself holds the same TTL, and the number of attempts of signing.
	// [There can be multiple mappings for the same signer].
	trackingIDToSigner map[string]*singleSigner

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

func hash(msg []byte) Digest {
	return sha3.Sum256(msg)
}

func (p *Impl) RemoveParticipantsFromSigningCommittee(digest Digest, removed SigningCommittee) (SigningCommittee, error) {

	// create new seed and generate new committee:
	newtrackid := seedFromSigningCommittee(digest, removed)
	// TODO: grab this signer, delete it and merge it with the original signer!
	// 		This might be a bit hard.
	seed := p.makeShuffleSeed(p.makeShuffleSeed(newtrackid))

	all := p.parameters.Parties().IDs()
	validParties := make([]*tss.PartyID, 0, len(all)-len(removed))

	if len(validParties) < p.parameters.Threshold()+1 {
		return nil, errors.New("not enough parties")
	}

	set := map[Digest]struct{}{}
	for _, party := range removed {
		set[pidToDigest(party.MessageWrapper_PartyID)] = struct{}{}
	}

	for _, party := range all {
		if _, ok := set[pidToDigest(party.MessageWrapper_PartyID)]; !ok {
			validParties = append(validParties, party)
		}
	}

	parties, err := shuffleParties(seed, validParties)
	if err != nil {
		return nil, err
	}
	parties = tss.SortPartyIDs(parties[:p.parameters.Threshold()+1])

	// changing the signer's inner state.
	signer, err := p.getOrCreateSingleSigner(digest[:])
	if err != nil {
		return nil, err
	}

	signer.mtx.Lock()
	signer.cleanManagementValues()
	signer.trackingId = newtrackid

	p.unsafeSetSignerState(parties, signer)
	signer.mtx.Unlock()

	s := p.signingHandler

	//ensuring the signer is found using its new trackingID.
	s.mtx.Lock()
	s.trackingIDToSigner[string(newtrackid)] = signer
	signer.mtx.Lock()

	p.setLocalParty(digest, signer)
	return nil, err
}

func (signer *singleSigner) cleanManagementValues() {
	panic("not ready.")
}

func seedFromSigningCommittee(digest Digest, parties SigningCommittee) []byte {
	seed := make([]byte, (len(parties)+1)*DigestSize)
	for i, party := range parties {
		tmpDigest := pidToDigest(party.MessageWrapper_PartyID)
		copy(seed[i*DigestSize:], tmpDigest[:])
	}

	copy(seed[len(parties)*DigestSize:], digest[:])
	return seed
}

func (p *Impl) ResetCommittee(digest Digest) error {
	// TODO implement me
	panic("implement me")
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
	for digest, signer := range s.trackingIDToSigner {

		signer.mtx.Lock()
		initTime := signer.time
		signer.mtx.Unlock()

		if currentTime.Sub(initTime) < maxTTL {
			nmap[digest] = signer
		}
	}

	s.trackingIDToSigner = nmap
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

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.state == notInCommittee {
		return ErrNotInSigningCommittee
	}

	if signer.state != set {
		return nil // might've changed before we got the lock. (due to the fault-tolerance)
	}

	if len(signer.messageBuffer) <= 0 {
		return nil
	}

	for _, msgArr := range signer.messageBuffer {
		for _, message := range msgArr {
			// TODO: consider what to do with changed committee issues.
			ok, err := signer.unsafeFeedLocalParty(message)
			if !ok {
				p.reportError(err)
			}
		}
	}

	return nil
}

// The signer isn't necessarily allowed to sign. as a result, we might return a nil signer - to ensure
// we don't sign messages blindly.
func (p *Impl) getSignerOrCacheMessage(message tss.ParsedMessage) (*singleSigner, *tss.Error) {
	signer, err := p.getOrCreateSingleSigner(message.WireMsg().GetTrackingID())
	if err != nil {
		return nil, tss.NewTrackableError(err, "get tss.signer", -1, nil, message.WireMsg().TrackingID)
	}

	shouldSign := signer.attemptToCacheIfShouldNotSign(message)
	if !shouldSign {
		return nil, nil
	}

	return signer, nil
}

func (p *Impl) getStartedSigner(digest Digest) (*singleSigner, error) {
	signer, err := p.getOrCreateSingleSigner(digest[:])
	if err != nil {
		return nil, err
	}

	if err := p.setLocalParty(digest, signer); err != nil {
		return nil, err
	}

	return signer, nil
}

// Since storing to cache is done strictly when this signer had not yet started to sign, this
// method will return a bool indicating whether it is allowed to sign.
func (signer *singleSigner) attemptToCacheIfShouldNotSign(message tss.ParsedMessage) (shouldSign bool) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	if signer.state == set {
		shouldSign = true
		return
	}

	// Else we store the messages. we might not be in the committee right now,
	// but this signer might be later consolidated with the committee (due to changes with the committee).
	dgst := pidToDigest(message.GetFrom().MessageWrapper_PartyID)

	if len(signer.messageBuffer[dgst]) < maxStoragePerParty {
		signer.messageBuffer[dgst] = append(signer.messageBuffer[dgst], message)
	}

	return
}

func (signer *singleSigner) feedLocalParty(msg tss.ParsedMessage) (bool, *tss.Error) {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	return signer.unsafeFeedLocalParty(msg)
}

func (signer *singleSigner) unsafeFeedLocalParty(msg tss.ParsedMessage) (bool, *tss.Error) {
	index, ok := signer.partyIdToIndex[pidToDigest(msg.GetFrom().MessageWrapper_PartyID)]
	if !ok {
		// committee changed, and this party is no longer in the committee.
		return true, nil
	}

	msg.GetFrom().Index = int(index) // setting the index of the according to the current committee.

	if signer.state != set {
		// can't feed a local party that hasn't started yet.
		return false, tss.NewTrackableError(fmt.Errorf("can't feed unset signer"), "", -1, nil, msg.WireMsg().TrackingID)
	}

	if !bytes.Equal(signer.trackingId, msg.WireMsg().TrackingID) {
		// tracking id changes due to fault tolarance order.
		// trackid is always advancing. so if we have something reaching this,
		// then it is old.
		return true, nil
	}

	return signer.localParty.Update(msg)
}

func pidToDigest(pid *tss.MessageWrapper_PartyID) Digest {
	bf := bytes.NewBuffer(nil)
	bf.WriteString(pid.Id)
	bf.Write(pid.Key)
	return hash(bf.Bytes())
}

var ErrNotInSigningCommittee = errors.New("self not in signing committee")
var ErrNoSigningKey = errors.New("no key to sign with")

// setLocalParty is used to prepare for signing, it creates a localParty instance for the signer.
// It can fail if the party isn't in the signing committee, or if there's no key to sign with.
func (p *Impl) setLocalParty(digest Digest, signer *singleSigner) error {
	secrets := p.keygenHandler.getSavedParams()
	if secrets == nil {
		return ErrNoSigningKey
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	d := Digest{}
	copy(d[:], digest[:])
	signer.digest = &d

	switch signer.state {
	case set:
		return nil

	case notInCommittee:
		return ErrNotInSigningCommittee

	case unset:

		trackid := make([]byte, len(signer.trackingId))
		copy(trackid, signer.trackingId) // setting the latest tracking id.

		signer.localParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			trackid, // track id is what we use to identify the signer throughout messages.
			p.makeParams(signer.comittee, signer.self),
			*secrets,
			p.outChan,
			p.signatureOutputChannel,
			DigestSize,
		)

		if err := signer.localParty.Start(); err != nil && err.Cause() != nil {
			return err.Cause()
		}

		signer.state = set
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
func (p *Impl) getOrCreateSingleSigner(trackingId []byte) (*singleSigner, error) {
	s := p.signingHandler
	strTrackingID := string(trackingId)

	s.mtx.Lock()
	defer s.mtx.Unlock()

	signer, ok := s.trackingIDToSigner[strTrackingID]
	if !ok {
		s.trackingIDToSigner[strTrackingID] = &singleSigner{
			time:          time.Now(),
			messageBuffer: map[Digest][]tss.ParsedMessage{},
			trackingId:    trackingId,

			digest: nil, // no digest yet.

			partyIdToIndex: map[Digest]partyIdIndex{},
			localParty:     nil,

			mtx:   sync.Mutex{},
			state: unset,
		}
		signer = s.trackingIDToSigner[strTrackingID]

		parties, err := shuffleParties(p.makeShuffleSeed(trackingId), p.parameters.Parties().IDs())
		if err != nil {
			return nil, err
		}

		parties = tss.SortPartyIDs(parties[:p.parameters.Threshold()+1])

		p.unsafeSetSignerState(parties, signer)
	}

	return signer, nil
}

func (p *Impl) makeShuffleSeed(digest []byte) []byte {
	seed := append(p.loadDistributionSeed, digest...)
	return seed
}

func (p *Impl) unsafeSetSignerState(parties []*tss.PartyID, signer *singleSigner) {
	if signer.self = p.selfInSigningCommittee(parties); signer.self == nil {
		signer.state = notInCommittee
	}

	for _, party := range parties {
		signer.partyIdToIndex[pidToDigest(party.MessageWrapper_PartyID)] = partyIdIndex(party.Index)
	}

	signer.comittee = parties
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
