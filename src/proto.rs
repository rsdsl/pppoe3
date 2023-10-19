use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Interval;

use serde::{de::DeserializeOwned, Serialize};

/// A protocol state as described in RFC 1661 section 4.2.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ProtocolState {
    #[default]
    Initial, // Lower layer down, no Open has occured, no restart timer
    Starting,    // Lower layer down, Open initiated, no restart timer; Up triggers Cfg-Req
    Closed,      // Lower layer up, no Open has occured, no restart timer; Cfg-Req triggers Term-Ack
    Stopped, // Lower layer up, Open initiated, no restart timer; Cfg-Req handled, * triggers Term-Ack
    Closing, // Term-Req sent, restart timer running, no Term-Ack received
    Stopping, // Like Closing, but transitions to Stopped, not Closed
    RequestSent, // Cfg-Req sent, no Cfg-Ack (either direction), restart timer running
    AckReceived, // Cfg-Req sent, Cfg-Ack received, no Cfg-Ack sent, restart timer running
    AckSent, // Cfg-Req and Cfg-Ack sent, no Cfg-Ack received, restart timer running
    Opened,  // Cfg-Ack sent and received, no restart timer; this layer is up
}

/// List of valid packet types for `Packet`s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketType {
    ConfigureRequest,
    ConfigureAck,
    ConfigureNak,
    ConfigureReject,
    TerminateRequest,
    TerminateAck,
}

/// A packet that can be a Configure-Request, Configure-Ack, Configure-Nak,
/// Configure-Reject, Terminate-Request or Terminate-Ack.
#[derive(Debug)]
pub struct Packet<O: Option> {
    pub ty: PacketType,
    pub options: Vec<O>,
}

/// A generic PPP option.
pub trait Option: Eq + Serialize + DeserializeOwned {}

/// A sub-protocol that implements the PPP Option Negotiation mechanism
/// as per RFC 1661 section 4. Used to manage individual protocols.
#[derive(Debug)]
pub struct NegotiationProtocol<O: Option> {
    require: Vec<O>,
    deny: Vec<O>,
    deny_exact: Vec<O>,
    request: Vec<O>, // mutated during negotiation
    refuse: Vec<O>,
    refuse_exact: Vec<O>,

    peer: Vec<O>,

    state: ProtocolState,

    restart_timer: Interval,

    max_terminate: u32,
    max_configure: u32,
    max_failure: u32,

    output_tx: mpsc::UnboundedSender<Packet<O>>,
    output_rx: mpsc::UnboundedReceiver<Packet<O>>,
}

impl<O: Option> NegotiationProtocol<O> {
    /// Creates a new `NegotiationProtocol` with the following characteristics:
    ///
    /// * `require` - Options to require the peer to set including a suggestion
    /// * `deny` - Options not to accept under any circumstances
    /// * `deny_exact` - Options not to accept if they have a listed value
    /// * `request` - Options to request initially
    /// * `refuse` - Options not to accept suggestions for under any circumstances
    /// * `refuse_exact` - Options not to accept the listed suggestion values for
    ///
    /// * `restart_interval` - The retransmission interval (Restart Timer), default is 3 seconds.
    /// * `max_terminate` - The maximum number of Term-Reqs to send, default is 2.
    /// * `max_configure` - The maximum number of Configure-Reqs to send, default is 10.
    /// * `max_failure` - The maximum number of Cfg-Naks sent before rejecting, default is 5.
    ///
    /// The resulting `processor` **must** be spawned before using the `Negotiator`.
    pub fn new(
        require: Vec<O>,
        deny: Vec<O>,
        deny_exact: Vec<O>,
        request: Vec<O>,
        refuse: Vec<O>,
        refuse_exact: Vec<O>,
        restart_interval: Option<Duration>,
        max_terminate: Option<u32>,
        max_configure: Option<u32>,
        max_failure: Option<u32>,
    ) -> Self {
        let restart_timer =
            tokio::time::interval(restart_interval.unwrap_or(Duration::from_secs(3)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();

        Self {
            require,
            deny,
            deny_exact,
            request,
            refuse,
            refuse_exact,

            peer: Vec::default(),

            state: ProtocolState::default(),

            restart_timer, // needs to be reset by some events

            max_terminate: max_terminate.unwrap_or(2),
            max_configure: max_configure.unwrap_or(10),
            max_failure: max_failure.unwrap_or(5),

            output_tx,
            output_rx,
        }
    }

    /// Waits for and returns the next packet to send.
    pub async fn to_send(&mut self) -> Packet<O> {
        // TODO:
        // select!:
        // Pass on packets from channel populated by from_recv.
        // Watch timers and counters.
        // Mutate state if necessary.
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RCR+, RCR-, RCA, RCN, RTR, RTA or RUC events.
    pub fn from_recv(&mut self, packet: Packet<O>) {
        // TODO:
        // Process packet and construct outbound packet if necessary.
        // Mutate requested options as needed.
    }

    /// Signals to the state machine that the lower layer is now up.
    /// This is equivalent to the Up event.
    pub fn up(&mut self) {}

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {}

    /// Issues an administrative open, allowing the protocol to start negotiation.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {}

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {}
}
