package party

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSigning(t *testing.T) {
	t.Run("single signature", func(t *testing.T) { testSigning(t, 1) })
	t.Run("five signatures ", func(t *testing.T) { testSigning(t, 5) })
}

func testSigning(t *testing.T, numSignatures int) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	digestSet := make(map[Digest]bool)
	for i := 0; i < numSignatures; i++ {
		d := crypto.Keccak256([]byte("hello, world" + strconv.Itoa(i)))
		hash := Digest{}
		copy(hash[:], d)
		digestSet[hash] = false
	}

	n := networkSimulator{
		outchan:         make(chan tss.Message, len(parties)*1000),
		sigchan:         make(chan *common.SignatureData, test.TestParticipants),
		errchan:         make(chan *tss.Error, 1),
		idToFullParty:   idToParty(parties),
		digestsToVerify: digestSet,
		Timeout:         time.Second * 20 * time.Duration(len(digestSet)),
	}

	for _, p := range parties {
		a.NoError(p.Start(n.outchan, n.sigchan, n.errchan))
	}

	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		n.run(a)
	}()

	for digest := range digestSet {
		go func(digest Digest) {
			for _, party := range parties {
				a.NoError(party.AsyncRequestNewSignature(digest))
			}
		}(digest)
	}

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

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

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
	impl.SigningHandler.Mtx.Lock()
	singleSigner, ok := impl.SigningHandler.DigestToSigner[string(hash[:])]
	a.True(ok)
	// unless request to sign something, LocalParty should remain nil.
	a.Nil(singleSigner.LocalParty)
	a.GreaterOrEqual(len(singleSigner.MessageBuffer), 1) // ensures this party received at least one message from others
	parties[len(parties)-1].(*Impl).SigningHandler.Mtx.Unlock()

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

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

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

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)
	maxTTL := time.Second * 1
	for _, impl := range parties {
		impl.(*Impl).MaxTTl = maxTTL
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

	p1.SigningHandler.Mtx.Lock()
	a.Lenf(p1.SigningHandler.DigestToSigner, 1, "expected 1 signer ")
	p1.SigningHandler.Mtx.Unlock()
	<-time.After(maxTTL * 2)

	p1.SigningHandler.Mtx.Lock()
	a.Lenf(p1.SigningHandler.DigestToSigner, 0, "expected 0 signers ")
	p1.SigningHandler.Mtx.Unlock()

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
		idToFullParty[p.(*Impl).PartyID.Id] = p
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
			a.NoError(err)
			a.FailNow("unexpected error")

		// simulating the network:
		case newMsg := <-n.outchan:
			passMsg(a, newMsg, n.idToFullParty)

		case m := <-n.sigchan:
			d := Digest{}
			copy(d[:], m.M)
			verified, ok := n.digestsToVerify[d]
			a.True(ok)

			if !verified {
				a.True(validateSignature(anyParty.getPublic(), m, m.M))
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

func passMsg(a *assert.Assertions, newMsg tss.Message, idToParty map[string]FullParty) {
	bz, routing, err := newMsg.WireBytes()
	a.NoError(err)
	// parsedMsg doesn't contain routing, since it assumes this message arrive for this participant from outside.
	// as a result we'll use the routing of the wireByte msgs.
	parsedMsg, err := tss.ParseWireMessage(bz, routing.From, routing.IsBroadcast)
	a.NoError(err)

	if routing.IsBroadcast || routing.To == nil {
		for pID, p := range idToParty {
			if routing.From.GetId() == pID {
				continue
			}
			a.NoError(p.Update(parsedMsg))
		}

		return
	}

	for _, id := range routing.To {
		a.NoError(idToParty[id.Id].Update(parsedMsg))
	}
}

func makeTestParameters(a *assert.Assertions, participants, threshold int) []Parameters {
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold+1, participants)
	a.NoError(err, "should load keygen fixtures")

	ps := make([]Parameters, 0, len(signPIDs))
	for i := 0; i < len(signPIDs); i++ {
		params := Parameters{
			savedParams: &keys[i],
			partyIDs:    signPIDs,
			Self:        signPIDs[i],
			Threshold:   threshold,
			SecretKey:   nil,
			WorkDir:     "",
		}
		ps = append(ps, params)
	}

	return ps
}

func createFullParties(a *assert.Assertions, participants, threshold int) ([]FullParty, []Parameters) {
	params := makeTestParameters(a, participants, threshold)
	parties := make([]FullParty, len(params))

	for i := range params {
		p, err := NewFullParty(&params[i])
		a.NoError(err)
		parties[i] = p
	}
	return parties, params
}
