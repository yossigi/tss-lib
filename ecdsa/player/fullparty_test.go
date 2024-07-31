package player

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	a := assert.New(t)

	parties, params := createFullParties(a, test.TestParticipants, test.TestThreshold+1)

	pk := params[0].savedParams.ECDSAPub

	outchan := make(chan tss.Message, 1)
	sigchan := make(chan *common.SignatureData, test.TestParticipants)
	errchan := make(chan *tss.Error, 1)
	for _, p := range parties {
		a.NoError(p.Start(outchan, sigchan, errchan))
	}

	// TODO create message "passer"

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

func makeTestParameters(a *assert.Assertions, participants, threshold int) []Parameters {
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold, participants)
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
