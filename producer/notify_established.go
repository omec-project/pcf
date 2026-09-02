// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/metrics"
	"github.com/omec-project/pcf/polling"
	"github.com/omec-project/pcf/util"
)

// defaultPolicyNotificationRate bounds the notification fan-out when nothing is configured.
//
// Sized from the air interface rather than from this element: each notification ends in a radio
// reconfiguration for one subscriber, and on a satellite link the round trip alone is most of a
// second. Ten per second spreads a slice-wide change over a period the radio can absorb while
// still applying it in a time an operator would call immediate. A deployment should set this
// from its own link budget; measurement sizes the default, it does not decide whether the bound
// exists.
const defaultPolicyNotificationRate = 10

// maxConsecutiveNotifyFailures bounds how long a fan-out keeps trying against an SMF that is not
// answering. Each failed send can cost the HTTP client's full timeout, so a large slice-wide
// change would otherwise spend minutes discovering the same thing repeatedly.
const maxConsecutiveNotifyFailures = 3

// sendNotification is a seam: the tests need to observe what was sent and to make sending fail,
// and the real one performs a synchronous HTTP request.
var sendNotification = notifyevent.SendSMPolicyUpdateNotification

func init() {
	// Registered here rather than wired from service: the polling package cannot import this one.
	polling.OnPolicyControlChanged = NotifyEstablishedSessions
}

// inFlight guards against a second fan-out starting while one is still running. A policy that
// changes twice in quick succession must not put two paced streams on the air interface at once,
// and the later one would be working from the same recomputed state anyway.
var inFlight atomic.Bool

// pendingNotification is one session that needs telling about a new policy.
type pendingNotification struct {
	notifyURI    string
	notification models.SmPolicyNotification
	// smPolicy and decision are held so the recomputed decision can be recorded once the SMF has
	// actually received it, and not before. See dispatchPaced.
	smPolicy *pcfContext.UeSmPolicyData
	decision *models.SmPolicyDecision
	// basedOn is the decision the merge was computed from, kept so the dispatcher can tell whether
	// anything replaced it while this notification waited its turn.
	basedOn     *models.SmPolicyDecision
	arpPriority int32
	smPolicyID  string
}

// NotifyEstablishedSessions brings sessions that are already running onto a policy that has just
// changed, instead of leaving them on the one they were given until they next re-establish.
//
// It reaches slice-level policy only. The hook fires from the policy-control poll, so a change to
// a network slice's PCC rules is seen, and a change to a **subscriber's** QoS is not: per-IMSI
// session rules come from a different endpoint (`/nfconfig/qos/{dnn}/{imsi}`), fetched per session
// on demand rather than polled, so nothing here notices when one changes. An operator editing a
// device group's 5QI, ARP or session AMBR therefore still waits for the subscriber to re-establish.
//
// Closing that is not a matter of removing the gate: there is no cached per-IMSI QoS to compare
// against, so detecting a change would mean fetching every established subscriber's rules on every
// poll — one HTTP request per session every five seconds. The recompute below already costs one
// such request per session, which is why it runs off the poll goroutine; doing it unconditionally
// would put that cost on every poll instead of on every policy change.
//
// Only sessions whose decision actually differs are notified. A configuration change that leaves
// a session's authorized parameters alone costs nothing to skip and a radio reconfiguration to
// send.
func NotifyEstablishedSessions() {
	// The guard is taken before recomputing, not after.
	//
	// Recomputing writes each changed session's new decision into the context. Doing that and
	// then finding the guard already held would leave the sessions holding decisions the SMF was
	// never told about, and the next comparison would match — so the change would be invisible
	// from then on, and the reassurance that it "will be picked up by the next change" would be
	// exactly wrong.
	if !inFlight.CompareAndSwap(false, true) {
		logger.SMpolicylog.Warnf("a policy notification fan-out is already running; this change will be recomputed when it finishes")
		return
	}

	// Everything below runs off the caller's goroutine, recompute included.
	//
	// The caller is the configuration poll loop, a single serial goroutine, and both halves of
	// this are slow for the same reason: they are per-session network work. Recomputing a
	// session's decision calls polling.GetImsiSessionRules, which is an HTTP GET to the webconsole
	// with a five second timeout — one per established session — and the paced dispatch that
	// follows takes minutes by design. Doing either inline would stop the PCF seeing any
	// configuration change for as long as it ran, and a degraded webconsole would both cause that
	// and be the thing the PCF could no longer poll.
	go func() {
		defer inFlight.Store(false)

		pending := recomputeChangedSessions()
		if len(pending) == 0 {
			logger.SMpolicylog.Debugln("policy changed but no established session's decision moved")
			return
		}

		// Highest allocation and retention priority first. TS 23.501 clause 5.7.2.2: the ARP
		// priority range is 1 to 15 with 1 as the highest, so this is ascending. If sessions must
		// wait, the ones being promoted are not the ones at the back of the queue.
		sortByPriority(pending)

		dispatchPaced(pending)
	}()
}

// sortByPriority orders the fan-out so the most important sessions are notified first.
//
// TS 23.501 clause 5.7.2.2: the ARP priority range is 1 to 15 with 1 as the highest, so this is
// ascending. Stable, so sessions at equal priority are not reshuffled between polls.
func sortByPriority(pending []pendingNotification) {
	sort.SliceStable(pending, func(i, j int) bool {
		return pending[i].arpPriority < pending[j].arpPriority
	})
}

// recomputeChangedSessions rebuilds the slice-derived part of each established session's decision
// against the new policy and returns the sessions whose decision moved.
//
// Only the four fields the slice policy contributes are replaced. Everything else in a stored
// decision is per-session and cannot be rebuilt from configuration: SuppFeat was negotiated with
// the SMF that created the session, PolicyCtrlReqTriggers tells that SMF what to report on, and
// Online, Offline and the IP indices came from the subscriber's UDR record. Rebuilding a whole
// decision from the slice policy would silently drop all of it, and would also make every session
// differ from its stored decision on every edit — so the comparison below would stop meaning
// anything and every session would be notified with a downgraded policy.
//
// This is why the merge starts from a copy of what is stored rather than listing what to carry
// over: a field nobody here knows about is preserved by construction.
//
// The stored policy context is the input, which is what makes a Session-AMBR change invisible
// here: it arrived from the SMF at policy-create time, sourced from subscription data, and is not
// part of the polled configuration. Only what the slice policy contributes can change.
func recomputeChangedSessions() []pendingNotification {
	var pending []pendingNotification

	pcfContext.PCF_Self().UePool.Range(func(_, value any) bool {
		ue, ok := value.(*pcfContext.UeContext)
		if !ok {
			return true
		}

		// Snapshot the map under its lock, then work outside it. Iterating while a session is
		// created or released elsewhere is a fatal runtime error, and the work below is long
		// enough — recomputing a decision per session — that holding the lock across it would
		// stall session setup for every subscriber on this UE.
		ue.SmPolicyDataMu.RLock()
		sessions := make(map[string]*pcfContext.UeSmPolicyData, len(ue.SmPolicyData))
		for id, smPolicy := range ue.SmPolicyData {
			sessions[id] = smPolicy
		}
		ue.SmPolicyDataMu.RUnlock()

		for smPolicyID, smPolicy := range sessions {
			if smPolicy == nil || smPolicy.PolicyContext == nil {
				continue
			}
			if smPolicy.PolicyDecision == nil {
				continue
			}

			// A session an application function is managing is left alone. The AF installs its own
			// PCC rules and QoS data into this same decision, and nothing in the data model records
			// which entries came from the AF and which from the slice policy — so replacing the
			// slice-derived part would take the AF's rules with it, stranding the app-session that
			// still references them and never crediting its GBR back. Reaching these sessions needs
			// provenance the decision does not yet carry.
			if smPolicy.HasAppSessions() {
				logger.SMpolicylog.Infof("session %s is managed by an application function; leaving its policy alone",
					smPolicyID)
				continue
			}

			ctx := smPolicy.PolicyContext
			sliceInfo := ctx.GetSliceInfo()

			// A session with nowhere to send a notification is not recomputed at all. Updating what
			// is stored and then finding there is no URI would leave the session holding a decision
			// it was never told about, and the next comparison would match, so the discrepancy would
			// never be visible again.
			notifyURI := ctx.GetNotificationUri()
			if notifyURI == "" {
				logger.SMpolicylog.Warnf("session %s has no notification URI; it cannot be told about a policy change",
					smPolicyID)
				continue
			}

			recomputed, problem := buildSmPolicyDecision(
				ue.Supi, sliceInfo, ctx.GetDnn(), ctx.SubsSessAmbr, ctx.SubsDefQos)
			if problem != nil || recomputed == nil {
				logger.SMpolicylog.Warnf("could not recompute policy for session %s: %v",
					smPolicyID, problem)
				continue
			}

			merged := mergeSliceDerived(smPolicy.PolicyDecision, recomputed)
			if reflect.DeepEqual(*smPolicy.PolicyDecision, merged) {
				continue
			}

			// Deliberately not stored here. The stored decision is what the next recompute
			// compares against, so writing it now and then failing to deliver would make the
			// change invisible from then on — the difference that would trigger a retry is the
			// one that has just been erased. It is recorded in dispatchPaced, once the SMF has
			// answered.
			decision := merged
			pending = append(pending, pendingNotification{
				notifyURI:   notifyURI,
				smPolicyID:  smPolicyID,
				smPolicy:    smPolicy,
				decision:    &decision,
				basedOn:     smPolicy.PolicyDecision,
				arpPriority: defaultQosArpPriority(&decision),
				notification: models.SmPolicyNotification{
					ResourceUri: openapi.PtrString(util.GetResourceUri(
						models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID)),
					SmPolicyDecision: &decision,
				},
			})
		}
		return true
	})

	return pending
}

// mergeSliceDerived returns the stored decision with only the slice-policy-derived fields taken
// from the recomputed one. See recomputeChangedSessions for why it copies rather than enumerates.
func mergeSliceDerived(stored, recomputed *models.SmPolicyDecision) models.SmPolicyDecision {
	merged := *stored
	merged.SessRules = recomputed.SessRules
	merged.PccRules = recomputed.PccRules
	merged.QosDecs = recomputed.QosDecs
	merged.TraffContDecs = recomputed.TraffContDecs
	return merged
}

// dispatchPaced sends the notifications within the configured rate bound, and records each
// session's new decision only once the SMF has acknowledged it.
//
// The ordering is the whole point. The stored decision is what the next recompute compares
// against, so storing before delivery and then failing to deliver would leave the session holding
// a policy the SMF never received — and the difference that would have triggered a retry is the
// one that has just been erased. Storing after delivery costs a re-notification if the PCF
// restarts mid-fan-out, which is harmless, and buys a retry on the next policy change for every
// session that was not reached.
//
// This is where the poll-driven trigger differs from the application function path, which stores
// and dispatches fire-and-forget. An application function whose notification is lost can post its
// app-session again; nothing re-posts a configuration change.
func dispatchPaced(pending []pendingNotification) {
	rate := defaultPolicyNotificationRate
	if factory.PcfConfig.Configuration != nil && factory.PcfConfig.Configuration.PolicyNotificationRate > 0 {
		rate = factory.PcfConfig.Configuration.PolicyNotificationRate
	}
	interval := time.Second / time.Duration(rate)

	logger.SMpolicylog.Infof("notifying %d established sessions of a policy change at %d/s",
		len(pending), rate)

	var delivered, failed, skipped, consecutiveFailures int

	for i, p := range pending {
		// Re-checked here, not only at recompute. Pacing means a session can wait minutes in this
		// queue, and what was true when it was queued need not still be true. An application
		// function that claims the session meanwhile installs its PCC rules into the very decision
		// this notification carries a replacement for, and the SMF would be told to drop them.
		if p.smPolicy.HasAppSessions() || p.smPolicy.PolicyDecision != p.basedOn {
			logger.SMpolicylog.Infof("session %s changed while it was queued; leaving it to the next policy change",
				p.smPolicyID)
			skipped++
			continue
		}

		notification := p.notification
		if err := sendNotification(p.notifyURI, &notification); err != nil {
			failed++
			logger.SMpolicylog.Warnf("session %s was not told about the policy change: %v",
				p.smPolicyID, err)

			// Only a failure that says something about the far end counts toward giving up. A
			// session the SMF no longer holds answers 404 while every other session is fine, and
			// counting those would let a few stale sessions abandon the fan-out and strand the
			// healthy ones behind them — the opposite of what the bound is for.
			if errors.Is(err, notifyevent.ErrSessionRejected) {
				consecutiveFailures = 0
				continue
			}
			consecutiveFailures++

			// A run of failures means the far end is down, not that these particular sessions were
			// unlucky. Continuing would spend the client timeout per session against an SMF that is
			// not answering, and every one of them would fail the same way.
			if consecutiveFailures >= maxConsecutiveNotifyFailures {
				notAttempted := len(pending) - i - 1
				logger.SMpolicylog.Errorf("giving up after %d consecutive failures: %d of %d sessions keep their previous policy until it changes again",
					consecutiveFailures, failed+skipped+notAttempted, len(pending))
				metrics.AddPcfPolicyNotifyStats("failed", failed)
				metrics.AddPcfPolicyNotifyStats("abandoned", notAttempted)
				metrics.AddPcfPolicyNotifyStats("skipped", skipped)
				metrics.AddPcfPolicyNotifyStats("delivered", delivered)
				return
			}
			continue
		}

		consecutiveFailures = 0
		delivered++

		// Checked once more, after the send and not only before it. The round trip above takes
		// milliseconds, and an application function that claims the session inside that window has
		// already written its PCC rules into the decision this store would replace:
		// mergeSliceDerived swaps the rule and QoS maps wholesale, so the AF's entries would go
		// with them and its app-session would be left referencing rules the PCF no longer holds.
		// Not storing costs a re-notification on the next policy change, which is the same price
		// every other session that could not be reached pays.
		if p.smPolicy.HasAppSessions() || p.smPolicy.PolicyDecision != p.basedOn {
			logger.SMpolicylog.Infof("session %s was claimed while it was being notified; leaving its stored policy alone",
				p.smPolicyID)
		} else {
			// Recorded only now. Until the SMF has it, this session's stored decision has to keep
			// saying what the SMF believes, or the next recompute finds nothing to send.
			p.smPolicy.PolicyDecision = p.decision
		}

		if i < len(pending)-1 {
			time.Sleep(interval)
		}
	}

	if failed > 0 || skipped > 0 {
		logger.SMpolicylog.Warnf("policy change reached %d of %d established sessions (%d failed, %d changed while queued); the rest are retried on the next change",
			delivered, len(pending), failed, skipped)
	} else {
		// A fan-out takes minutes by design, so an operator watching a slice-wide change needs a
		// line saying it finished, not only the one saying it started.
		logger.SMpolicylog.Infof("policy change reached all %d established sessions", delivered)
	}
	metrics.AddPcfPolicyNotifyStats("delivered", delivered)
	metrics.AddPcfPolicyNotifyStats("failed", failed)
	metrics.AddPcfPolicyNotifyStats("skipped", skipped)
}

// defaultQosArpPriority reports the ARP priority a session should be paced by, taking the most
// important flow it has. An absent ARP sorts last, since nothing says it is urgent.
func defaultQosArpPriority(decision *models.SmPolicyDecision) int32 {
	best := int32(16) // one beyond the lowest real priority
	for _, qos := range decision.GetQosDecs() {
		if qos.Arp == nil {
			continue
		}
		if level := qos.Arp.GetPriorityLevel(); level > 0 && level < best {
			best = level
		}
	}
	return best
}
