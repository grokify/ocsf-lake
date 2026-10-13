// Package seed generates realistic, schema-valid OCSF test data for
// populating a lake: a weighted mix of event classes spread over a time
// window, with configurable proportions of signed, unsigned, and
// tampered-after-signing events, plus tamper-evident chains.
//
// Event content is deterministic for a given Config (including Seed);
// signature bytes are not, because ECDSA signing is randomized and signing
// authorities are generated per run — by design, key material is never
// checked in.
package seed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/grokify/ocsf-lake/pkg/lake"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

// Config controls generation.
type Config struct {
	// Events is the total number of events to generate (default 1000).
	Events int
	// Start and Span define the event-time window. Zero Start means
	// Span-before-now; zero Span means 30 days.
	Start time.Time
	Span  time.Duration
	// Seed drives all content randomness (default 1); the same Config
	// always yields the same event content.
	Seed int64
	// Sources are producer names cycled across events (default a built-in
	// set). The source also becomes metadata.product.name.
	Sources []string
	// Classes restricts generation to these template names (default: all).
	Classes []string
	// SignedPct is the percentage (0-100) of events signed by the
	// authority (default 0 = unsigned only).
	SignedPct float64
	// TamperPct is the percentage (0-100) of signed, non-chain events that
	// are tampered after signing, so integrity checks fail (default 0).
	TamperPct float64
	// Chains is the number of tamper-evident chains to weave through the
	// signed events; ChainLength (default 10) events each. Chain events
	// count toward Events and SignedPct.
	Chains      int
	ChainLength int
	// BreakChain corrupts one middle link of the last chain so chain
	// verification fails, for exercising chain_broken detection.
	BreakChain bool
	// Authority signs events; nil generates a fresh one (see NewAuthority).
	Authority *Authority
}

func (c *Config) setDefaults() error {
	if c.Events <= 0 {
		c.Events = 1000
	}
	if c.Span <= 0 {
		c.Span = 30 * 24 * time.Hour
	}
	if c.Start.IsZero() {
		c.Start = time.Now().Add(-c.Span)
	}
	if c.Seed == 0 {
		c.Seed = 1
	}
	if len(c.Sources) == 0 {
		c.Sources = []string{"okta", "sysmon", "zeek", "aws-cloudtrail"}
	}
	if c.ChainLength <= 0 {
		c.ChainLength = 10
	}
	if c.Chains*c.ChainLength > c.Events {
		return fmt.Errorf("seed: %d chains of length %d exceed %d total events", c.Chains, c.ChainLength, c.Events)
	}
	if (c.SignedPct > 0 || c.Chains > 0) && c.Authority == nil {
		auth, err := NewAuthority("seed-authority")
		if err != nil {
			return err
		}
		c.Authority = auth
	}
	return nil
}

// Event is one generated event with its ground truth, so tests can assert
// checker results exactly.
type Event struct {
	// ID is the storage identifier to ingest under.
	ID string
	// UID is the event's metadata.uid.
	UID string
	// JSON is the final event payload (signed/tampered as flagged).
	JSON []byte
	// Class is the OCSF class template name.
	Class string
	// Signed, Tampered, and ChainUID record what was done to the event.
	Signed   bool
	Tampered bool
	ChainUID string
}

// Result is the generated data set plus ground-truth counts.
type Result struct {
	Events    []Event
	Authority *Authority
	ChainUIDs []string

	Signed   int // signed and intact
	Tampered int // signed then tampered (integrity checks fail)
	Unsigned int
}

// Generate produces the data set described by cfg.
func Generate(cfg Config) (*Result, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(cfg.Seed)) //nolint:gosec // test data, not crypto

	allowed := map[string]bool{}
	for _, name := range cfg.Classes {
		if _, ok := templates[name]; !ok {
			return nil, fmt.Errorf("seed: unknown class template %q", name)
		}
		allowed[name] = true
	}

	// Evenly spaced, jittered, ascending timestamps keep chains coherent
	// and time-range queries meaningful.
	step := cfg.Span.Milliseconds() / int64(cfg.Events)
	if step < 1 {
		step = 1
	}
	baseMS := cfg.Start.UnixMilli()

	res := &Result{Authority: cfg.Authority}

	// Decide which slots are signed, and which signed slots form chains.
	signedTarget := int(float64(cfg.Events)*cfg.SignedPct/100.0 + 0.5)
	if min := cfg.Chains * cfg.ChainLength; signedTarget < min {
		signedTarget = min
	}
	if signedTarget > cfg.Events {
		signedTarget = cfg.Events
	}
	signedSlots := map[int]bool{}
	for _, idx := range rng.Perm(cfg.Events)[:signedTarget] {
		signedSlots[idx] = true
	}
	// Chains claim the first N signed slots in time order.
	var signedOrder []int
	for i := 0; i < cfg.Events; i++ {
		if signedSlots[i] {
			signedOrder = append(signedOrder, i)
		}
	}
	chainOf := map[int]int{} // slot -> chain number
	for chain := 0; chain < cfg.Chains; chain++ {
		uid := fmt.Sprintf("seed-chain-%02d", chain+1)
		res.ChainUIDs = append(res.ChainUIDs, uid)
		for j := 0; j < cfg.ChainLength; j++ {
			chainOf[signedOrder[chain*cfg.ChainLength+j]] = chain
		}
	}

	chainTails := make([][]byte, cfg.Chains)
	brokenSlot := -1

	for i := 0; i < cfg.Events; i++ {
		uid := fmt.Sprintf("uid-%06d", i+1)
		source := cfg.Sources[i%len(cfg.Sources)]
		timeMS := baseMS + int64(i)*step + rng.Int63n(step)
		class := pickClass(rng, allowed)

		evt := templates[class](rng, uid, source, timeMS)
		payload, err := json.Marshal(evt)
		if err != nil {
			return nil, fmt.Errorf("seed: marshaling %s event: %w", class, err)
		}

		ev := Event{ID: fmt.Sprintf("seed-%06d", i+1), UID: uid, Class: class, JSON: payload}
		if signedSlots[i] {
			signOpts := ri.SignOptions{
				Signer:       cfg.Authority.Signer,
				Certificate:  cfg.Authority.Certificate,
				AuthorityUID: cfg.Authority.Name,
			}
			chain, inChain := chainOf[i]
			if inChain {
				signOpts.ChainUID = res.ChainUIDs[chain]
				if tail := chainTails[chain]; tail != nil {
					if signOpts.PrevEvent, err = ri.NewPrevEventRef(tail); err != nil {
						return nil, err
					}
				}
				ev.ChainUID = signOpts.ChainUID
			}
			signed, _, err := ri.SignAndAttach(payload, signOpts)
			if err != nil {
				return nil, fmt.Errorf("seed: signing event %d: %w", i, err)
			}
			ev.JSON = signed
			ev.Signed = true
			if inChain {
				chainTails[chain] = signed
				// Remember a middle link of the last chain to corrupt.
				if cfg.BreakChain && chain == cfg.Chains-1 && chainTails[chain] != nil && brokenSlot == -1 && signOpts.PrevEvent != nil {
					brokenSlot = len(res.Events)
				}
			} else if cfg.TamperPct > 0 && rng.Float64()*100 < cfg.TamperPct {
				if ev.JSON, err = tamper(ev.JSON); err != nil {
					return nil, err
				}
				ev.Tampered = true
			}
		}

		res.Events = append(res.Events, ev)
		switch {
		case ev.Tampered:
			res.Tampered++
		case ev.Signed:
			res.Signed++
		default:
			res.Unsigned++
		}
	}

	if cfg.BreakChain && brokenSlot >= 0 {
		broken, err := tamper(res.Events[brokenSlot].JSON)
		if err != nil {
			return nil, err
		}
		res.Events[brokenSlot].JSON = broken
		res.Events[brokenSlot].Tampered = true
		res.Signed--
		res.Tampered++
	}

	return res, nil
}

// tamper modifies a signed payload after the fact (simulating storage-layer
// corruption) while keeping it schema-valid: the message attribute changes,
// so the content fingerprint no longer matches.
func tamper(payload []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	msg, err := json.Marshal("tampered after signing")
	if err != nil {
		return nil, err
	}
	m["message"] = msg
	return json.Marshal(m)
}

// Populate ingests the generated events into a lake via IngestWithID.
func (r *Result) Populate(ctx context.Context, l *lake.Lake) error {
	for _, ev := range r.Events {
		if err := l.IngestWithID(ctx, ev.ID, ev.JSON); err != nil {
			return fmt.Errorf("seed: ingesting %s (%s): %w", ev.ID, ev.Class, err)
		}
	}
	return nil
}

// NDJSON writes the generated events one per line, for piping into
// `ocsflake ingest`.
func (r *Result) NDJSON(w io.Writer) error {
	for _, ev := range r.Events {
		if _, err := w.Write(append(ev.JSON, '\n')); err != nil {
			return err
		}
	}
	return nil
}
