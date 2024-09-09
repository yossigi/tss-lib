package party

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/test"
	"github.com/yossigi/tss-lib/v2/tss"
)

var (
	smallFixturesLocation = path.Join(getProjectRootDir(), "test", "_ecdsa_quick")
	largeFixturesLocation = path.Join(getProjectRootDir(), "test", "_ecdsa_fixtures")
)

func getProjectRootDir() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	abs, err := filepath.Abs(wd)
	if err != nil {
		panic(err)
	}

	for {
		cur := filepath.Dir(abs)
		if cur == "" {
			panic("could not find project root")
		}

		if !strings.Contains(cur, "tss-lib") {
			break
		}
		abs = cur

	}

	return abs
}

func TestSigning(t *testing.T) {
	st := signerTester{
		participants:             test.TestParticipants,
		threshold:                test.TestThreshold,
		numSignatures:            1,
		keygenLocation:           largeFixturesLocation,
		maxNetworkSimulationTime: time.Second * 200,
	}
	t.Run("one signature", st.run)

	st.numSignatures = 5
	st.maxNetworkSimulationTime = time.Second * 200
	t.Run("five signatures ", st.run)

	st2 := signerTester{
		participants:             5,
		threshold:                3,
		numSignatures:            50,
		keygenLocation:           path.Join(getProjectRootDir(), "test", "_ecdsa_quick"),
		maxNetworkSimulationTime: time.Minute,
	}
	t.Run("3 threshold 20 signatures", st2.run)
}

type signerTester struct {
	participants, threshold, numSignatures int
	keygenLocation                         string
	maxNetworkSimulationTime               time.Duration
}

func (st *signerTester) run(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, st.participants, st.threshold, st.keygenLocation)

	digestSet := make(map[Digest]bool)
	for i := 0; i < st.numSignatures; i++ {
		d := crypto.Keccak256([]byte("hello, world" + strconv.Itoa(i)))
		hash := Digest{}
		copy(hash[:], d)
		digestSet[hash] = false
	}

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, st.participants),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         st.maxNetworkSimulationTime,
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	for digest := range digestSet {

		for _, party := range parties {
			err := party.AsyncRequestNewSignature(digest)
			if ErrNotInSigningCommittee == err {
				continue
			}

			a.NoError(err)
		}
	}

	time.Sleep(time.Second * 5)
	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	fmt.Println("Setup done. test starting.")

	fmt.Println("ngoroutines:", runtime.NumGoroutine())
	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

/*
Test to ensure that a Part will not attempt to sign a digest, even if received messages to sign from others.
*/
func TestPartyDoesntFollowRouge(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold, largeFixturesLocation)

	digestSet := make(map[Digest]bool)
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)
	digestSet[hash] = false

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 3,
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	for i := 0; i < len(parties)-1; i++ {
		a.NoError(parties[i].AsyncRequestNewSignature(hash))
	}

	<-donechan
	impl := parties[len(parties)-1].(*Impl)

	// test:
	impl.signingHandler.mtx.Lock()
	singleSigner, ok := impl.signingHandler.digestToSigner[string(hash[:])]
	a.True(ok)
	// unless request to sign something, LocalParty should remain nil.
	a.Nil(singleSigner.localParty)
	a.GreaterOrEqual(len(singleSigner.messageBuffer), 1) // ensures this party received at least one message from others
	parties[len(parties)-1].(*Impl).signingHandler.mtx.Unlock()

	for _, party := range parties {
		party.Stop()
	}

}
func TestMultipleRequestToSignSameThing(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, 5, 3, smallFixturesLocation)

	digestSet := make(map[Digest]bool)
	for i := 0; i < 1; i++ {
		d := crypto.Keccak256([]byte("hello, world" + strconv.Itoa(i)))
		hash := Digest{}
		copy(hash[:], d)
		digestSet[hash] = false
	}

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, 5),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 20 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	for digest := range digestSet {
		for i := 0; i < 10; i++ {
			go func(digest Digest) {
				for _, party := range parties {
					a.NoError(party.AsyncRequestNewSignature(digest))
				}
			}(digest)
		}
	}

	time.Sleep(time.Second)

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	fmt.Println("Setup done. test starting.")

	fmt.Println("ngoroutines:", runtime.NumGoroutine())
	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

func TestLateParties(t *testing.T) {
	t.Run("single late party", func(t *testing.T) { testLateParties(t, 1) })
	t.Run("multiple late parties", func(t *testing.T) { testLateParties(t, 5) })
}

func testLateParties(t *testing.T, numLate int) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold, largeFixturesLocation)

	digestSet := make(map[Digest]bool)
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)
	digestSet[hash] = false

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 3,
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	for i := 0; i < len(parties)-numLate; i++ {
		a.NoError(parties[i].AsyncRequestNewSignature(hash))
	}

	<-donechan
	a.False(n.verifiedAllSignatures())

	for i := len(parties) - numLate; i < len(parties); i++ {
		a.NoError(parties[i].AsyncRequestNewSignature(hash))
	}

	n.Timeout = time.Second * 20
	donechan2 := make(chan struct{})
	go func() {
		defer close(donechan2)
		n.run(a)
	}()

	<-donechan2
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}

func TestCleanup(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold, largeFixturesLocation)
	maxTTL := time.Second * 1
	for _, impl := range parties {
		impl.(*Impl).maxTTl = maxTTL
	}
	n := networkSimulator{
		outchan: make(chan tss.Message, len(parties)*20),
		sigchan: make(chan *common.SignatureData, test.TestParticipants),
		errchan: make(chan *tss.Error, 1),
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}
	p1 := parties[0].(*Impl)
	digest := Digest{}
	a.NoError(p1.AsyncRequestNewSignature(digest))

	p1.signingHandler.mtx.Lock()
	a.Lenf(p1.signingHandler.digestToSigner, 1, "expected 1 signer ")
	p1.signingHandler.mtx.Unlock()
	<-time.After(maxTTL * 2)

	p1.signingHandler.mtx.Lock()
	a.Lenf(p1.signingHandler.digestToSigner, 0, "expected 0 signers ")
	p1.signingHandler.mtx.Unlock()

	for _, party := range parties {
		party.Stop()
	}
}

type networkSimulator struct {
	outchan         chan tss.Message
	sigchan         chan *common.SignatureData
	errchan         chan *tss.Error
	idToFullParty   map[string]FullParty
	digestsToVerify map[Digest]bool // states whether it was checked or not yet.

	Timeout time.Duration // 0 means no timeout
	// used to wait for errors
	expectErr bool
}

func (n *networkSimulator) verifiedAllSignatures() bool {
	for _, b := range n.digestsToVerify {
		if b {
			continue
		}
		return false
	}
	return true

}

func idToParty(parties []FullParty) map[string]FullParty {
	idToFullParty := map[string]FullParty{}
	for _, p := range parties {
		idToFullParty[p.(*Impl).partyID.Id] = p
	}
	return idToFullParty
}

func (n *networkSimulator) run(a *assert.Assertions) {
	var anyParty FullParty
	for _, p := range n.idToFullParty {
		anyParty = p
		break
	}

	a.NotNil(anyParty)

	after := time.After(n.Timeout)
	if n.Timeout == 0 {
		after = nil
	}

	for {
		select {
		case err := <-n.errchan:
			if n.expectErr {
				fmt.Println("Received expected error:", err)
				return
			}

			a.NoError(err)
			a.FailNow("unexpected error")

		// simulating the network:
		case newMsg := <-n.outchan:
			passMsg(a, newMsg, n.idToFullParty, n.expectErr)

		case m := <-n.sigchan:
			d := Digest{}
			copy(d[:], m.M)
			verified, ok := n.digestsToVerify[d]
			a.True(ok)

			if !verified {

				a.True(validateSignature(anyParty.GetPublic(), m, d[:]))
				n.digestsToVerify[d] = true
				fmt.Println("Signature validated correctly.", m)
				continue
			}

			if n.verifiedAllSignatures() {
				fmt.Println("All signatures validated correctly.")
				return
			}

		case <-after:
			fmt.Println("network timeout")
			return
		}
	}
}

func validateSignature(pk *ecdsa.PublicKey, m *common.SignatureData, digest []byte) bool {
	S := (&big.Int{}).SetBytes(m.S)
	r := (&big.Int{}).SetBytes(m.R)

	return ecdsa.Verify(pk, digest, r, S)

}

func passMsg(a *assert.Assertions, newMsg tss.Message, idToParty map[string]FullParty, expectErr bool) {
	bz, routing, err := newMsg.WireBytes()
	if expectErr && err != nil {
		return
	}
	a.NoError(err)
	// parsedMsg doesn't contain routing, since it assumes this message arrive for this participant from outside.
	// as a result we'll use the routing of the wireByte msgs.
	parsedMsg, err := tss.ParseWireMessage(bz, routing.From, routing.IsBroadcast)
	if expectErr && err != nil {
		return
	}
	a.NoError(err)

	if routing.IsBroadcast || routing.To == nil {
		for pID, p := range idToParty {
			if routing.From.GetId() == pID {
				continue
			}
			err = p.Update(parsedMsg)
			if expectErr && err != nil {
				continue
			}
			a.NoError(err)
		}

		return
	}

	for _, id := range routing.To {
		err = idToParty[id.Id].Update(parsedMsg)
		if expectErr && err != nil {
			continue
		}
		a.NoError(err)
	}
}

func makeTestParameters(a *assert.Assertions, participants, threshold int, location string) []Parameters {
	ps := make([]Parameters, participants)
	sortedIds := make([]*tss.PartyID, len(ps))

	for i := 0; i < len(ps); i++ {
		kg := KeygenHandler{
			StoragePath: location,
		}
		a.NoError(kg.setup(nil, &tss.PartyID{Index: i}))
		key := kg.SavedData.Ks[i]
		sortedIds[i] = tss.NewPartyID(key.String(), key.String(), key)

		ps[i] = Parameters{
			SavedSecrets:         kg.SavedData,
			PartyIDs:             sortedIds,
			Self:                 sortedIds[i],
			Threshold:            threshold,
			WorkDir:              "",  // using SavedSecrets - no need to concern with workDir.
			MaxSignerTTL:         0,   // letting it pick default.
			LoadDistributionSeed: nil, // using nil shared secret.
		}
	}

	return ps
}

func createFullParties(a *assert.Assertions, participants, threshold int, location string) ([]FullParty, []Parameters) {
	if location == "" {
		panic("location must be set")
	}

	params := makeTestParameters(a, participants, threshold, location)
	parties := make([]FullParty, len(params))

	for i := range params {
		p, err := NewFullParty(&params[i])
		a.NoError(err)
		parties[i] = p
	}
	return parties, params
}

func TestClosingThreadpoolMidRun(t *testing.T) {
	// This test Fails when not run in isolation.
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold, largeFixturesLocation)

	digestSet := make(map[Digest]bool)
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)
	digestSet[hash] = false

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*20),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 8,
		expectErr:       true,
	}

	goroutinesstart := runtime.NumGoroutine()

	chanReceivedAsyncTask := make(chan struct{})
	barrier := make(chan struct{})
	var visitedFlag int32 = 0
	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))

		tmp, ok := p.(*Impl)
		a.True(ok)

		fnc := tmp.parameters.AsyncWorkComputation
		// setting different AsyncWorkComputation to test closing the threadpool
		tmp.parameters.AsyncWorkComputation = func(f func()) error {
			select {
			// signaling we reached an async function
			case chanReceivedAsyncTask <- struct{}{}:
			default:
			}

			<-barrier
			atomic.AddInt32(&visitedFlag, 1)
			return fnc(f)
		}
	}

	a.Equal(
		len(parties)*(runtime.NumCPU()*2+1)+goroutinesstart,
		runtime.NumGoroutine(),
		"expected each party to add 2*numcpu workers and 1 cleanup gorotuines",
	)

	for i := 0; i < len(parties); i++ {
		a.NoError(parties[i].AsyncRequestNewSignature(hash))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	// stopping everyone to close the threadpools.
	<-chanReceivedAsyncTask
	for _, party := range parties {
		party.Stop()
	}
	close(barrier)
	<-donechan

	time.Sleep(time.Second * 3)
	a.True(atomic.LoadInt32(&visitedFlag) > 0, "expected to visit the async function")

	a.Equal(goroutinesstart, runtime.NumGoroutine(), "expected same number of goroutines at the end")
}

func TestTrailingZerosInDigests(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, 5, 3, smallFixturesLocation)

	digestSet := make(map[Digest]bool)

	hash1 := Digest{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	digestSet[hash1] = false

	hash2 := Digest{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	digestSet[hash2] = false

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, 5),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 20 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	for digest := range digestSet {
		go func(digest Digest) {
			for _, party := range parties {
				a.NoError(party.AsyncRequestNewSignature(digest))
			}
		}(digest)
	}

	time.Sleep(time.Second)

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	<-donechan
	a.True(n.verifiedAllSignatures())

	for _, party := range parties {
		party.Stop()
	}
}
