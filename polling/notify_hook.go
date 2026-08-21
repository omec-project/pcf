// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package polling

// OnPolicyControlChanged is called after a polled policy change has been installed in the cache,
// so that sessions already established can be brought to the new policy rather than waiting for
// each subscriber to re-establish.
//
// It is a hook rather than a direct call because the code that recomputes a session's decision
// lives in the producer package, which imports this one. The producer registers itself.
//
// Called with no locks held: the cache rebuild has finished, and dispatching notifications while
// holding the configuration lock would block the next poll behind the air interface.
var OnPolicyControlChanged func()

func notifyPolicyControlChanged() {
	if OnPolicyControlChanged != nil {
		OnPolicyControlChanged()
	}
}
