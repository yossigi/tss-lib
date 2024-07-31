package player

import (
	"context"
	"crypto/ecdsa"
	"sync"

	utils "github.com/bnb-chain/tss-lib/v2/ecdsa/ethereum"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type Parameters struct {
	// a path in the filesystem where data and files can be saved.
	SaveDirPath string

	partyIDs []*tss.PartyID
	Self     *tss.PartyID

	Threshold int

	// P2P keys for generating signature all Players should recognise, more formally, this SecretKey should be tied
	// to the encoded public key in the Self field
	SecretKey *ecdsa.PrivateKey // TODO: this isn't really needed by this package, but by a reliable broadcast package
}

type Digest [32]byte

type FullParty interface {
	// Start will set up the FullParty, and few sub-components (including few goroutines).
	// outChannel: will be used by this Party to request messages to be sent outside,
	//      these messages can be either broadcast requests (using protocol like reliable broadcast),
	//      or uni-cast requests (which should be encrypted)
	// signatureOutputChannel: will be used by this Party to output a signature
	//      which should be aggragated by a relay and constructed into a single ecdsa signature.
	// TODO: add to tss.Message Metadata() function.
	Start(outChannel chan tss.Message, signatureOutputChannel chan utils.EthContractSignature, errChannel chan<- *tss.Error)

	// Stop will Stop the FullPlarty
	Stop()

	// AsyncRequestNewSignature begins the signing protocol over the given digest.
	AsyncRequestNewSignature(Digest) error

	// Update will Update the FullParty with the ParsedMessage
	// while running the protocol.
	Update(tss.ParsedMessage) error
}

type emptyWriter struct{}

func (e emptyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
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
			StoragePath:       p.SaveDirPath,
			Out:               nil, // set up during Start()
			ProtocolEndOutput: make(chan *keygen.LocalPartySaveData, 1),

			// to be set correctly during Start()
			LocalParty: nil,
			SavedData:  nil,
		},
		SigningHandler: &SigningHandler{
			Mtx:              sync.RWMutex{},
			DigestToSigner:   map[string]SingleSigner{},
			OutChan:          nil, // set up during Start()
			SigPartReadyChan: nil, // set up during Start()
		},
		incomingMessagesChannel: make(chan tss.ParsedMessage),
		// TODO: not sure this is needed
		IdToPIDmapping: map[string]*tss.PartyID{},
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
