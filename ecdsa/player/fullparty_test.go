package player

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	a := assert.New(t)

	parties, _ := createFullParties(a, test.TestParticipants, test.TestThreshold)

	<-SingleSignatureTestHelper(a, parties)

	for _, party := range parties {
		party.Stop()
	}
}

func SingleSignatureTestHelper(a *assert.Assertions, parties []FullParty) chan struct{} {
	outchan := make(chan tss.Message, len(parties)*20)
	sigchan := make(chan *common.SignatureData, test.TestParticipants)
	errchan := make(chan *tss.Error, 1)
	for _, p := range parties {
		a.NoError(p.Start(outchan, sigchan, errchan))
	}

	// setup:
	d := crypto.Keccak256([]byte("hello, world"))
	hash := Digest{}
	copy(hash[:], d)

	idToFullParty := map[string]FullParty{}
	for _, p := range parties {
		idToFullParty[p.(*Impl).PartyID.Id] = p
	}

	// network simulation:
	donechan := make(chan struct{})
	go func() {
		defer close(donechan)
		networkSimulator(a, errchan, outchan, sigchan, idToFullParty, hash)
	}()

	// setting a single message to sign for all players.
	for _, party := range parties {
		a.NoError(party.AsyncRequestNewSignature(hash))
	}

	return donechan
}

func networkSimulator(
	a *assert.Assertions,
	errchan chan *tss.Error,
	outchan chan tss.Message,
	sigchan chan *common.SignatureData,
	idToFullParty map[string]FullParty,
	hash Digest) {

	var anyParty FullParty
	for _, p := range idToFullParty {
		anyParty = p
		break
	}
	a.NotNil(anyParty)

	for {
		select {
		case err := <-errchan:
			a.NoError(err)
			a.FailNow("unexpected error")

		// simulating the network:
		case newMsg := <-outchan:
			passMsg(a, newMsg, idToFullParty)

		// the following happens locally on each player. we simulate what each player will do after it's done with DKG
		case m := <-sigchan:
			validateSignature(a, anyParty.getPublic(), m, hash[:])
			fmt.Println("Signature validated correctly. ", m)
			return

		case <-time.Tick(time.Millisecond * 500):
			fmt.Println("ticked")
		}
	}
}

func validateSignature(a *assert.Assertions, pk *ecdsa.PublicKey, m *common.SignatureData, msgToSign []byte) {
	digest := m.M
	a.Equal(digest, msgToSign)
	S := (&big.Int{}).SetBytes(m.S)
	r := (&big.Int{}).SetBytes(m.R)

	a.True(ecdsa.Verify(pk, digest, r, S))
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
		parties[i] = NewFullParty(&params[i])
	}
	return parties, params
}
