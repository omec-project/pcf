// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"reflect"
	"sort"
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
	pending := recomputeChangedSessions()
	if len(pending) == 0 {
		logger.SMpolicylog.Debugln("policy changed but no established session's decision moved")
		return
	}

	// Highest allocation and retention priority first. TS 23.501 clause 5.7.2.2: the ARP priority
	// range is 1 to 15 with 1 as the highest, so this is ascending. If sessions must wait, the
	// ones being promoted are not the ones at the back of the queue.
	sortByPriority(pending)

	dispatchPaced(pending)
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

// recomputeChangedSessions rebuilds each established session's decision against the new policy
// and returns those that moved.
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

		for smPolicyID, smPolicy := range ue.SmPolicyData {
			if smPolicy == nil || smPolicy.PolicyContext == nil {
				continue
			}
			ctx := smPolicy.PolicyContext
			sliceInfo := ctx.GetSliceInfo()

			recomputed, problem := buildSmPolicyDecision(
				ue.Supi, sliceInfo, ctx.GetDnn(), ctx.SubsSessAmbr, ctx.SubsDefQos)
			if problem != nil || recomputed == nil {
				logger.SMpolicylog.Warnf("could not recompute policy for session %s: %v",
					smPolicyID, problem)
				continue
			}

			if reflect.DeepEqual(smPolicy.PolicyDecision, recomputed) {
				continue
			}

			smPolicy.PolicyDecision = recomputed
			pending = append(pending, pendingNotification{
				notifyURI:   ctx.GetNotificationUri(),
				smPolicyID:  smPolicyID,
				arpPriority: defaultQosArpPriority(recomputed),
				notification: models.SmPolicyNotification{
					ResourceUri: openapiPtr(util.GetResourceUri(
						models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID)),
					SmPolicyDecision: recomputed,
				},
			})
		}
		return true
	})

	return pending
}

// dispatchPaced sends the notifications within the configured rate bound.
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
