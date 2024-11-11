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
	comittee       tss.SortedPartyIDs
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

func (p *Impl) AsyncRequestNewSignature(digest Digest) (*SigningInfo, error) {
	signer, err := p.getStartedSigner(digest)
	if err != nil {
		return nil, err
	}

	// TODO: YOSSI: I'm not sure I like p.getStartedSigner, since it grabs a lock and then we release it,
	// 		do you think i should merge the function above into this function since it's only used here?
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	info := &SigningInfo{
		SigningCommittee: signer.comittee,
		TrackingID:       signer.trackingId,
		IsSigner:         isInComittee(signer.self, tss.UnSortedPartyIDs(signer.comittee)),
	}

	if signer.state == notInCommittee {
		return info, nil
	}

	if signer.state != set {
		return info, nil // might've changed before we got the lock. (due to the fault-tolerance)
	}

	if len(signer.messageBuffer) <= 0 {
		return info, nil
	}

	for _, msgArr := range signer.messageBuffer {
		for _, message := range msgArr {
			ok, err := signer.unsafeFeedLocalParty(message)
			if !ok {
				p.reportError(err)
			}
		}
	}

	return info, nil
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
	trackid, _ := makeAdjustedTrackingId(digest, nil)

	signer, err := p.getOrCreateSingleSigner(trackid[:])
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

	// fmt.Println("Recived msg of type:", msg.Type())
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

var ErrNoSigningKey = errors.New("no key to sign with")

// setLocalParty is used to prepare for signing, it creates a localParty instance for the signer.
// It can fail if the party isn't in the signing committee, or if there's no key to sign with.
func (p *Impl) setLocalParty(digest Digest, signer *singleSigner) error {
	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	return p.unsafeSetLocalParty(signer, digest)
}

func isInComittee(self *tss.PartyID, comittee tss.UnSortedPartyIDs) bool {
	return indexInComittee(self, tss.UnSortedPartyIDs(comittee)) != -1
}

func indexInComittee(self *tss.PartyID, comittee tss.UnSortedPartyIDs) int {
	for i, v := range comittee {
		if equalIDs(v, self) {
			return i
		}
	}

	return -1
}

func (p *Impl) unsafeSetLocalParty(signer *singleSigner, digest Digest) error {
	secrets := p.keygenHandler.getSavedParams()
	if secrets == nil {
		return ErrNoSigningKey
	}

	signer.digest = &digest

	switch signer.state {
	case set:
		return nil

	case notInCommittee:
		return nil // not an error

	case unset:
		// check if notInCommittee:

		index := indexInComittee(signer.self, tss.UnSortedPartyIDs(signer.comittee))
		if index == -1 {
			signer.state = notInCommittee
			return nil
		}

		signer.state = set
		// updating the self to a copy with a different index
		// (matching the indices of the current committee).
		signer.self = signer.comittee[index]

		// setting the latest tracking id.
		trackid := make([]byte, len(signer.trackingId))
		copy(trackid, signer.trackingId)

		signer.localParty = signing.NewLocalParty(
			(&big.Int{}).SetBytes(digest[:]),
			// track id is what we use to identify the signer throughout messages.
			trackid,
			p.makeParams(signer.comittee, signer.self),
			*secrets,
			p.outChan,
			p.signatureOutputChannel,
			DigestSize,
		)

		if err := signer.localParty.Start(); err != nil && err.Cause() != nil {
			return err.Cause()
		}
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
	p.signingHandler.mtx.Lock()
	defer p.signingHandler.mtx.Unlock()

	return p.unsafeGetOrCreateSingleSigner(trackingId)
}

func (p *Impl) unsafeGetOrCreateSingleSigner(trackingId []byte) (*singleSigner, error) {
	strTrackingID := string(trackingId)

	s := p.signingHandler

	signer, ok := s.trackingIDToSigner[strTrackingID]
	if !ok {
		s.trackingIDToSigner[strTrackingID] = &singleSigner{
			time:          time.Now(),
			self:          p.partyID,
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

		signer.unsafeSetCommittee(tss.SortPartyIDs(parties[:p.parameters.Threshold()+1]))
	}

	return signer, nil
}

func (p *Impl) makeShuffleSeed(digest []byte) []byte {
	seed := append(p.loadDistributionSeed, digest...)
	return seed
}

func equalIDs(a, b *tss.PartyID) bool {
	return a.Id == b.Id && bytes.Equal(a.Key, b.Key)
}

func (signer *singleSigner) unsafeSetCommittee(parties []*tss.PartyID) {
	signer.partyIdToIndex = make(map[Digest]partyIdIndex, len(parties))

	for _, party := range parties {
		pidDigest := pidToDigest(party.MessageWrapper_PartyID)
		signer.partyIdToIndex[pidDigest] = partyIdIndex(party.Index)
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

func (p *Impl) RemovePariticipantsFromSigning(digest Digest, removed tss.UnSortedPartyIDs) (*UpdatedSigningInfo, error) {
	newtrackid, sortedRemoved := makeAdjustedTrackingId(digest, removed)

	newcomittee, err := p.removedComittee(newtrackid, sortedRemoved)
	if err != nil {
		return nil, err
	}

	updated, err := p.resetSigner(digest, newcomittee, newtrackid)
	if err != nil {
		return nil, err
	}

	if !updated.NewSigningInfo.IsSigner {
		return updated, nil
	}

	signer := updated.signer
	msgs := updated.bufferMessages

	for _, msg := range msgs {
		ok, err := signer.feedLocalParty(msg)
		if !ok {
			p.reportError(err)
		}
	}

	return updated, nil
}

func bufferToArray(msgBuffer map[Digest][]tss.ParsedMessage) []tss.ParsedMessage {
	res := []tss.ParsedMessage{}
	for _, v := range msgBuffer {
		res = append(res, v...)
	}

	return res
}

func (p *Impl) resetSigner(digest Digest, newcomittee tss.SortedPartyIDs, newtrackid []byte) (*UpdatedSigningInfo, error) {
	s := p.signingHandler

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Getting the signer for the digest -> one that hadn't seen any faults yet.
	// adding the new information (trackingID, and the new committee), and resetting the signer.
	noFaultsTrackid, noFaultsComittee := makeAdjustedTrackingId(digest, nil)
	signer, err := p.unsafeGetOrCreateSingleSigner(noFaultsTrackid)
	if err != nil {
		return nil, err
	}

	signer.mtx.Lock()
	defer signer.mtx.Unlock()

	unmerged, exists := s.trackingIDToSigner[string(newtrackid)]
	if signer == unmerged {
		// we already reset this signer (the new trackid points to it too).
		// no need to do it again, return with the "new" info.
		return &UpdatedSigningInfo{
			OldSigningCommittee: noFaultsComittee,
			NewSigningInfo: SigningInfo{
				SigningCommittee: signer.comittee, // probably the same.
				TrackingID:       newtrackid,      // the same.
				IsSigner:         isInComittee(signer.self, tss.UnSortedPartyIDs(signer.comittee)),
			},
			bufferMessages: nil, // not supposed to make use of buffer in this case.
			signer:         signer,
		}, nil
	}

	// Resseting the signer, updating tracking id, and the committee.
	oldState := signer.state

	signer.localParty = nil  // deleting the old localparty.
	signer.state = unset     // we are now unset.
	signer.time = time.Now() // resetting the init time.

	signer.digest = &digest

	// oldTrackindID := signer.trackingId
	signer.trackingId = newtrackid // deleting the old one

	oldComittee := signer.comittee
	signer.unsafeSetCommittee(newcomittee)

	msgBuffer := bufferToArray(signer.messageBuffer)
	signer.messageBuffer = map[Digest][]tss.ParsedMessage{} // dropping the old messages.

	// We saw the trackid (probably because a different FullParty reset their signer before we did).
	// performing a few checks, and attempting to merge the two signers into one.
	if exists {
		unmerged.mtx.Lock()
		defer unmerged.mtx.Unlock()

		if (unmerged.digest != nil && signer.digest != nil) && (*unmerged.digest != *signer.digest) {
			return nil, errors.New("new trackingid collided") // unfortunate. sha3 collison is very unlikely.
		}

		if unmerged.state == set {
			// TODO: what to do here? can this happen? this means TWO different signers, with the same digest
			// but not the same tracking id. which is very unlikely.
			return nil, errors.New("two signers with the same digest, different tracking id and one of them is set")
		} else {
			msgBuffer = append(msgBuffer, bufferToArray(unmerged.messageBuffer)...)
		}
	}

	// ensuring the signer is found using its new trackingID too.
	// potentially, writing over "unmerged" if it exists, so the new and set signer is used.
	// Notice that multiple pointers to the same signer are stored,
	// so incoming messages for different trackingIDs will get handled by that signer.
	s.trackingIDToSigner[string(newtrackid)] = signer

	retinfo := &UpdatedSigningInfo{
		OldSigningCommittee: oldComittee,
		NewSigningInfo: SigningInfo{
			SigningCommittee: newcomittee,
			TrackingID:       newtrackid,
			IsSigner:         isInComittee(signer.self, tss.UnSortedPartyIDs(signer.comittee)),
		},

		bufferMessages: msgBuffer,
		signer:         signer,
	}

	if oldState == unset {
		return retinfo, nil
	}

	if err := p.unsafeSetLocalParty(signer, digest); err != nil {
		return nil, err
	}

	return retinfo, nil
}

func (p *Impl) removedComittee(newtrackid []byte, removed tss.SortedPartyIDs) (tss.SortedPartyIDs, error) {
	seed := p.makeShuffleSeed(p.makeShuffleSeed(newtrackid))

	all := p.parameters.Parties().IDs()
	validParties := make([]*tss.PartyID, 0, len(all)-len(removed))

	if cap(validParties) < p.parameters.Threshold()+1 {
		return nil, fmt.Errorf("not enough parties: %d < %d",
			cap(validParties),
			p.parameters.Threshold()+1,
		)
	}

	set := map[Digest]struct{}{}
	for _, party := range removed {
		set[pidToDigest(party.MessageWrapper_PartyID)] = struct{}{}
	}

	for _, party := range all {
		if _, ok := set[pidToDigest(party.MessageWrapper_PartyID)]; ok {
			continue
		}

		validParties = append(validParties, party)
	}

	parties, err := shuffleParties(seed, validParties)
	if err != nil {
		return nil, err
	}

	return tss.SortPartyIDs(parties[:p.parameters.Threshold()+1]), nil
}

func makeAdjustedTrackingId(digest Digest, faulties tss.UnSortedPartyIDs) ([]byte, tss.SortedPartyIDs) {
	// Requesting sorted faulies since  it ensures deterministic results
	// between different FullParties.
	// For instance: party one sees {2,1} in the removed, and party two sees {1,2},
	// to ensure both create the same tracking ID they sort it so both use {1,2}, when
	// computing the new tracking ID.
	sortedRemoved := tss.SortPartyIDs(faulties)

	seed := make([]byte, (len(sortedRemoved)+1)*DigestSize)
	for i, party := range sortedRemoved {
		tmp := pidToDigest(party.MessageWrapper_PartyID)
		copy(seed[i*DigestSize:], tmp[:])
	}

	copy(seed[len(sortedRemoved)*DigestSize:], digest[:])

	tmp := hash(seed)
	return tmp[:], sortedRemoved
}

func (p *Impl) GetSigningInfo(digest Digest, faulties tss.UnSortedPartyIDs) (*SigningInfo, error) {
	trackid, sortedRemoved := makeAdjustedTrackingId(digest, faulties)

	sortedComittee, err := p.removedComittee(trackid, sortedRemoved)
	if err != nil {
		return nil, err
	}

	return &SigningInfo{
		SigningCommittee: sortedComittee,
		TrackingID:       trackid,
		IsSigner:         isInComittee(p.partyID, tss.UnSortedPartyIDs(sortedComittee)),
	}, nil
}
