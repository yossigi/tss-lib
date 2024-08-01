package player

import (
	"context"
	"crypto/ecdsa"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type Parameters struct {
	// for simplicity of testing:
	savedParams *keygen.LocalPartySaveData

	partyIDs []*tss.PartyID
	Self     *tss.PartyID

	Threshold int

	// P2P keys for generating signature all Players should recognise, more formally, this SecretKey should be tied
	// to the encoded public key in the Self field
	SecretKey *ecdsa.PrivateKey // TODO: this isn't really needed by this package, but by a reliable broadcast package
	WorkDir   string
}

type Digest [32]byte

type FullParty interface {
	// Start will set up the FullParty, and few sub-components (including few
	// goroutines). outChannel: will be used by this Party to request messages
	// to be sent outside, these messages can be either broadcast requests
	// (using protocol like reliable broadcast), or unicast requests (which
	// should be encrypted) signatureOutputChannel: will be used by this Party
	// to output a signature which should be aggragated by a relay and
	// constructed into a single ecdsa signature.
	Start(outChannel chan tss.Message, signatureOutputChannel chan *common.SignatureData, errChannel chan<- *tss.Error) error

	// Stop will Stop the FullPlarty
	Stop()

	// AsyncRequestNewSignature begins the signing protocol over the given digest.
	AsyncRequestNewSignature(Digest) error

	// Update will Update the FullParty with the ParsedMessage
	// while running the protocol.
	Update(tss.ParsedMessage) error

	getPublic() *ecdsa.PublicKey
}

// NewFullPlayer returns a new FullPlayer instance.
func NewFullParty(p *Parameters) FullParty {
	if p == nil {
		return nil
	}

	p.ensurePartiesContainsSelf()

	pctx := tss.NewPeerContext(tss.SortPartyIDs(p.partyIDs))
	ctx, cancelF := context.WithCancel(context.Background())
	imp := &Impl{
		ctx:         ctx,
		cancelFunc:  cancelF,
		SecretKey:   p.SecretKey,
		PartyID:     p.Self,
		PeerContext: pctx,
		Parameters:  tss.NewParameters(tss.S256(), pctx, p.Self, len(p.partyIDs), p.Threshold),
		KeygenHandler: &KeygenHandler{
			StoragePath:       p.WorkDir,
			ProtocolEndOutput: make(chan *keygen.LocalPartySaveData, 1),

			// to be set correctly during Start()
			LocalParty: nil,
			SavedData:  p.savedParams,
		},
		SigningHandler: &SigningHandler{
			Mtx:              sync.RWMutex{},
			DigestToSigner:   map[string]*SingleSigner{},
			SigPartReadyChan: nil, // set up during Start()
		},
		incomingMessagesChannel: make(chan tss.ParsedMessage),
		// TODO: not sure this is needed
		IdToPIDmapping: map[string]*tss.PartyID{},

		// the following fields should be provided in Start()
		errorChannel:           nil,
		OutChan:                nil,
		signatureOutputChannel: nil,
	}
	return imp
}

func (p *Parameters) ensurePartiesContainsSelf() {
	for _, party := range p.partyIDs {
		if party.Id == p.Self.Id {
			return
		}
	}

	p.partyIDs = append(p.partyIDs, p.Self)
}
