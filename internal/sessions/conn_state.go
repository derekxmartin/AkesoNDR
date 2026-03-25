package sessions

import "github.com/akesondr/akeso-ndr/internal/common"

// tcpFlags represents the set of TCP flags seen on a session, used to
// drive the conn_state finite state machine (Zeek model).
type tcpFlags struct {
	origSYN bool
	respSYN bool // SYN-ACK
	origFIN bool
	respFIN bool
	origRST bool
	respRST bool
	origData bool // any payload from originator
	respData bool // any payload from responder
}

// connState computes the Zeek-style connection state from observed TCP flags.
//
// States (from Zeek documentation):
//
//	S0   — SYN sent, no reply at all.
//	S1   — SYN-ACK seen (connection established), no data or close yet.
//	SF   — Normal establishment and termination (FIN from both sides).
//	REJ  — Connection attempt rejected (RST in response to SYN).
//	RSTO — Established, originator aborted with RST.
//	RSTR — Established, responder aborted with RST.
//	S2   — Established, originator sent FIN, no FIN from responder.
//	S3   — Established, responder sent FIN, no FIN from originator.
//	OTH  — No SYN seen (midstream pickup).
func connState(f *tcpFlags) common.ConnState {
	established := f.origSYN && f.respSYN

	// No SYN from originator — midstream pickup.
	if !f.origSYN {
		return common.ConnStateOTH
	}

	// SYN sent but no SYN-ACK.
	if !f.respSYN {
		if f.respRST {
			return common.ConnStateREJ
		}
		return common.ConnStateS0
	}

	// Established — check for RST.
	if established {
		if f.origRST {
			return common.ConnStateRSTO
		}
		if f.respRST {
			return common.ConnStateRSTR
		}
	}

	// Both FINs — normal close.
	if f.origFIN && f.respFIN {
		return common.ConnStateSF
	}

	// Only originator FIN.
	if f.origFIN {
		return common.ConnStateS2
	}

	// Only responder FIN.
	if f.respFIN {
		return common.ConnStateS3
	}

	// Established, no close yet.
	return common.ConnStateS1
}
