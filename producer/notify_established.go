// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/logger"
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
	arpPriority  int32
	smPolicyID   string
}

// NotifyEstablishedSessions brings sessions that are already running onto a policy that has just
// changed, instead of leaving them on the one they were given until they next re-establish.
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

	pending := recomputeChangedSessions()
	if len(pending) == 0 {
		logger.SMpolicylog.Debugln("policy changed but no established session's decision moved")
		inFlight.Store(false)
		return
	}

	// Highest allocation and retention priority first. TS 23.501 clause 5.7.2.2: the ARP priority
	// range is 1 to 15 with 1 as the highest, so this is ascending. If sessions must wait, the
	// ones being promoted are not the ones at the back of the queue.
	sortByPriority(pending)

	// Dispatched off the caller's goroutine. The caller is the configuration poll loop, and the
	// fan-out is deliberately slow — pacing a thousand sessions takes minutes. Blocking the loop
	// for that long would stop the SMF and the PCF seeing configuration changes at all, which is
	// the opposite of what a change meant to reach running sessions should cost.
	go func() {
		defer inFlight.Store(false)
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
			if len(smPolicy.AppSessions) > 0 {
				logger.SMpolicylog.Infof("session %s has %d active application sessions; leaving its policy alone",
					smPolicyID, len(smPolicy.AppSessions))
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

			stored := merged
			smPolicy.PolicyDecision = &stored
			pending = append(pending, pendingNotification{
				notifyURI:   notifyURI,
				smPolicyID:  smPolicyID,
				arpPriority: defaultQosArpPriority(&stored),
				notification: models.SmPolicyNotification{
					ResourceUri: openapiPtr(util.GetResourceUri(
						models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID)),
					SmPolicyDecision: &stored,
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

// dispatchPaced sends the notifications within the configured rate bound.
//
// Delivery is fire-and-forget: the dispatcher queues the event and a failure is logged by the
// sender, with no path back here. A session whose notification is dropped therefore keeps a
// stored decision the SMF never received, and because recomputeChangedSessions compares against
// that stored decision, the next poll sees no difference and never retries. The change is then
// invisible.
//
// The application function path stores and dispatches the same way, so this is not new — but the
// consequence is worse here, and that difference is the point. An application function whose
// notification is lost can post its app-session again; a poll-driven trigger that suppresses
// repeats has no equivalent, because the thing that would trigger a repeat is the very
// difference that has just been erased.
//
// Fixing it means knowing what was delivered rather than what was computed, which is a change to
// how the decision is recorded. Until then a dropped notification is a silent divergence, and the
// first step is to make it countable rather than only logged.
func dispatchPaced(pending []pendingNotification) {
	rate := factory.PcfConfig.Configuration.PolicyNotificationRate
	if rate <= 0 {
		rate = defaultPolicyNotificationRate
	}
	interval := time.Second / time.Duration(rate)

	logger.SMpolicylog.Infof("notifying %d established sessions of a policy change at %d/s",
		len(pending), rate)

	for i, p := range pending {
		if p.notifyURI == "" {
			logger.SMpolicylog.Warnf("session %s has no notification URI; it will not be told about the policy change",
				p.smPolicyID)
			continue
		}
		notification := p.notification
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(p.notifyURI, &notification)

		if i < len(pending)-1 {
			time.Sleep(interval)
		}
	}
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

func openapiPtr(s string) *string { return &s }
