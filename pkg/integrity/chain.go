package integrity

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/grokify/ocsf-lake/pkg/ocsf"
	ri "github.com/grokify/ocsf-schema-go/recordintegrity"
)

// chainInfo is the slice of an event payload the chain walker needs.
type chainInfo struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	AttestationList []struct {
		ChainUID  string `json:"chain_uid"`
		PrevEvent *struct {
			UID string `json:"uid"`
		} `json:"prev_event"`
	} `json:"attestation_list"`
}

// ChainReport is the outcome of verifying one tamper-evident chain.
type ChainReport struct {
	ChainUID string    `json:"chain_uid"`
	Report   *Report   `json:"report"`
	Heads    int       `json:"heads"` // chain members without a prev_event reference
	Started  time.Time `json:"started_at"`
	Finished time.Time `json:"finished_at"`
}

// CheckChain verifies one chain end to end: every member event is checked
// individually (fingerprint, signatures, certificates), and each prev_event
// link is verified against the resolved predecessor. Chain membership is
// determined by attestation chain_uid, which requires a payload scan.
func (c *Checker) CheckChain(ctx context.Context, chainUID string) (*ChainReport, error) {
	cr := &ChainReport{ChainUID: chainUID, Started: time.Now(), Report: &Report{StartedAt: time.Now()}}

	type member struct {
		ev      *ocsf.StoredEvent
		payload []byte
		info    chainInfo
	}
	var members []member
	byUID := map[string]*member{}

	err := c.sweep(ctx, nil, func(ev *ocsf.StoredEvent) {
		payload, err := json.Marshal(ev.Payload)
		if err != nil {
			return
		}
		var info chainInfo
		if err := json.Unmarshal(payload, &info); err != nil {
			return
		}
		inChain := false
		for _, att := range info.AttestationList {
			if att.ChainUID == chainUID {
				inChain = true
				break
			}
		}
		if !inChain {
			return
		}
		m := member{ev: ev, payload: payload, info: info}
		members = append(members, m)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ev.IngestedAt.Before(members[j].ev.IngestedAt) })
	for i := range members {
		if uid := members[i].info.Metadata.UID; uid != "" {
			byUID[uid] = &members[i]
		}
	}

	for _, m := range members {
		res := c.checkAndRecord(ctx, m.ev, cr.Report)

		hasPrev := false
		for _, att := range m.info.AttestationList {
			if att.ChainUID != chainUID || att.PrevEvent == nil {
				continue
			}
			hasPrev = true
			prev, ok := byUID[att.PrevEvent.UID]
			if !ok {
				res.Outcome = OutcomeFailed
				res.Status = worse(res.Status, ri.StatusChainBroken)
				res.Issues = append(res.Issues, ri.Issue{
					Status:  ri.StatusChainBroken,
					Message: "prev_event.uid " + att.PrevEvent.UID + " not found in chain " + chainUID,
				})
				continue
			}
			lr := ri.VerifyLink(m.payload, prev.payload)
			if lr.Status != ri.StatusVerified {
				res.Outcome = OutcomeFailed
				res.Status = worse(res.Status, lr.Status)
				res.Issues = append(res.Issues, lr.Issues...)
			}
		}
		if !hasPrev {
			cr.Heads++
		}
		cr.Report.record(res)
	}

	cr.Report.FinishedAt = time.Now()
	cr.Finished = cr.Report.FinishedAt
	c.saveReport(ctx, "chain", cr.Report, nil)
	return cr, nil
}

// worse returns the more severe of two statuses.
func worse(a, b ri.Status) ri.Status {
	if ri.SeverityRank(b) > ri.SeverityRank(a) {
		return b
	}
	return a
}
