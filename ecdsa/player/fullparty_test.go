package player

import (
	"crypto/ecdsa"
	"crypto/rand"
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

	parties, params := createFullParties(a, test.TestParticipants, test.TestThreshold)

	pk := params[0].savedParams.ECDSAPub

	outchan := make(chan tss.Message, len(parties)*20)
	sigchan := make(chan *common.SignatureData, test.TestParticipants)
	errchan := make(chan *tss.Error, 1)
	for _, p := range parties {
		a.NoError(p.Start(outchan, sigchan, errchan))
	}

	<-SingleSignatureTestHelper(a, parties, outchan, errchan, sigchan)

	p := parties[0]
	d := Digest{} // assuming this is the hash digest of some message
	_, _ = rand.Read(d[:])

	a.NoError(p.AsyncRequestNewSignature(d))

	sig := <-sigchan
	a.Equal(d[:], sig.M[:])

	a.True(ecdsa.Verify(pk.ToECDSAPubKey(), sig.M, (&big.Int{}).SetBytes(sig.R), (&big.Int{}).SetBytes(sig.S)))
	for _, party := range parties {
		party.Stop()
	}
}

func SingleSignatureTestHelper(a *assert.Assertions, parties []FullParty, outchan chan tss.Message, errchan chan *tss.Error, sigchan chan *common.SignatureData) chan struct{} {
	donechan := make(chan struct{})
	defer close(donechan)

	d := crypto.Keccak256([]byte("hello, world"))
	fmt.Println(d)
	hash := Digest{}
	copy(hash[:], d)

	idToFullParty := map[string]FullParty{}
	for _, p := range parties {
		idToFullParty[p.(*Impl).PartyID.Id] = p
	}

	// setting a single message to sign for all players.

	a.NoError(parties[0].AsyncRequestNewSignature(hash))

signerLoop:
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
			fmt.Println("Signature ready", m)

			validateSignature(a, parties[0].getPublic(), m, hash[:])
			break signerLoop

		case <-time.Tick(time.Millisecond * 500):
			fmt.Println("ticked")
		}
	}

	return donechan
}

func validateSignature(a *assert.Assertions, pk *ecdsa.PublicKey, m *common.SignatureData, msgToSign []byte) {
	digest := m.M
	a.Equal(digest, msgToSign)
	S := (&big.Int{}).SetBytes(m.S)
	r := (&big.Int{}).SetBytes(m.R)

	a.True(ecdsa.Verify(pk, digest, r, S))
}

func passMsg(a *assert.Assertions, newMsg tss.Message, idToParty map[string]FullParty) {
	fmt.Println(newMsg.Type())
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
