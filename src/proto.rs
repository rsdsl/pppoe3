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
    CodeReject,
    ProtocolReject,
    EchoRequest,
    EchoReply,
    DiscardRequest,
    Unknown,
}

/// A packet that can be a Configure-Request, Configure-Ack, Configure-Nak,
/// Configure-Reject, Terminate-Request or Terminate-Ack.
#[derive(Debug)]
pub struct Packet<O: ProtocolOption> {
    pub ty: PacketType,
    pub options: Vec<O>,
    pub rejected_code: PacketType,
    pub rejected_protocol: u16,
}

/// A generic PPP option.
pub trait ProtocolOption: Clone + Eq + Serialize + DeserializeOwned {
    fn has_same_type(&self, other: &Self) -> bool;
}

/// A sub-protocol that implements the PPP Option Negotiation mechanism
/// as per RFC 1661 section 4. Used to manage individual protocols.
#[derive(Debug)]
pub struct NegotiationProtocol<O: ProtocolOption> {
    require: Vec<O>,
    deny: Vec<O>,
    deny_exact: Vec<(O, O)>,
    request: Vec<O>, // mutated during negotiation
    refuse: Vec<O>,
    refuse_exact: Vec<O>,

    peer: Vec<O>,

    need_protocol_reject: bool,

    state: ProtocolState,

    restart_timer: Interval,
    restart_counter: u32,

    max_terminate: u32,
    max_configure: u32,
    max_failure: u32,

    output_tx: mpsc::UnboundedSender<Packet<O>>,
    output_rx: mpsc::UnboundedReceiver<Packet<O>>,
}

impl<O: ProtocolOption> NegotiationProtocol<O> {
    /// Creates a new `NegotiationProtocol` with the following characteristics:
    ///
    /// * `require` - Options to require the peer to set including a suggestion.
    /// * `deny` - Options not to accept under any circumstances.
    /// * `deny_exact` - Options not to accept if they have a listed value including a suggestion.
    /// * `request` - Options to request initially.
    /// * `refuse` - Options not to accept suggestions for under any circumstances.
    /// * `refuse_exact` - Options not to accept the listed suggestion values for.
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
        deny_exact: Vec<(O, O)>,
        request: Vec<O>,
        refuse: Vec<O>,
        refuse_exact: Vec<O>,
        need_protocol_reject: bool,
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

            need_protocol_reject,

            state: ProtocolState::default(),

            restart_timer,      // needs to be reset by some events
            restart_counter: 0, // needs to be (re)set by some events

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
        match packet.ty {
            PacketType::ConfigureRequest => {
                if self.is_acceptable(&packet.options) {
                    self.rcr_positive(packet)
                } else {
                    self.rcr_negative(packet)
                }
            }
            PacketType::ConfigureAck => self.rca(packet),
            PacketType::ConfigureNak | PacketType::ConfigureReject => self.rcn(packet),
            PacketType::TerminateRequest => self.rtr(packet),
            PacketType::TerminateAck => self.rta(packet),
            PacketType::Unknown => self.ruc(packet),
            PacketType::CodeReject => {
                if self.need_code(&packet.rejected_code) {
                    self.rxj_negative(packet)
                } else {
                    self.rxj_positive(packet)
                }
            }
            PacketType::ProtocolReject => {
                if Self::need_protocol(packet.rejected_protocol) {
                    self.rxj_negative(packet)
                } else {
                    self.rxj_positive(packet)
                }
            }
            PacketType::EchoRequest => {
                // TODO: Queue Echo-Reply transmission.
            }
        }
    }

    /// Signals to the state machine that the lower layer is now up.
    /// This is equivalent to the Up event.
    pub fn up(&mut self) {
        match self.state {
            ProtocolState::Initial => self.state = ProtocolState::Closed,
            ProtocolState::Starting => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {
        match self.state {
            ProtocolState::Closed => self.state = ProtocolState::Initial,
            ProtocolState::Stopped => self.state = ProtocolState::Starting, // tls action
            ProtocolState::Closing => self.state = ProtocolState::Initial,
            ProtocolState::Stopping => self.state = ProtocolState::Starting,
            ProtocolState::RequestSent => self.state = ProtocolState::Starting,
            ProtocolState::AckReceived => self.state = ProtocolState::Starting,
            ProtocolState::AckSent => self.state = ProtocolState::Starting,
            ProtocolState::Opened => self.state = ProtocolState::Starting, // tld action
                                                                           // TODO: Inform upper layers via a channel.
        }
    }

    /// Issues an administrative open, allowing the protocol to start negotiation.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {
        // The [r] (restart) implementation option is not implemented.
        match self.state {
            ProtocolState::Initial => self.state = ProtocolState::Starting, // tls action
            ProtocolState::Closed => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Closing => self.state = ProtocolState::Stopping,
        }
    }

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {
        match self.state {
            ProtocolState::Starting => self.state = ProtocolState::Initial, // tlf action
            ProtocolState::Stopped => self.state = ProtocolState::Closed,
            ProtocolState::Stopping => self.state = ProtocolState::Closing,
            ProtocolState::RequestSent | ProtocolState::AckReceived | ProtocolState::AckSent => {
                self.restart_timer.reset();
                self.restart_counter = self.max_terminate;

                self.output_tx.send(Packet {
                    ty: PacketType::TerminateRequest,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });
                self.restart_counter -= 1;

                self.state = ProtocolState::Closing;
            }
            ProtocolState::Opened => {
                // tld action
                // TODO: Inform upper layers via a channel.

                self.restart_timer.reset();
                self.restart_counter = self.max_terminate;

                self.output_tx.send(Packet {
                    ty: PacketType::TerminateRequest,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });
                self.restart_counter -= 1;

                self.state = ProtocolState::Closing;
            }
        }
    }

    fn rcr_positive(&mut self, packet: Packet<O>) {
        match self.state {
            ProtocolState::Closed => self
                .output_tx
                .send(Packet {
                    ty: PacketType::TerminateAck,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::Stopped => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureAck,
                    options: packet.options,
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.state = ProtocolState::AckSent;
            }
            ProtocolState::RequestSent => {
                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureAck,
                    options: packet.options,
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.state = ProtocolState::AckSent;
            }
            ProtocolState::AckReceived => {
                // tlu action
                // TODO: Inform upper layers via a channel.

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureAck,
                    options: packet.options,
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.state = ProtocolState::Opened;
            }
            ProtocolState::AckSent => self
                .output_tx
                .send(Packet {
                    ty: PacketType::ConfigureAck,
                    options: packet.options,
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::Opened => {
                // tld action
                // TODO: Inform upper layers via a channel.

                self.restart_timer.reset();

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureAck,
                    options: packet.options,
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                self.state = ProtocolState::AckSent;
            }
        }
    }

    fn rcr_negative(&mut self, packet: Packet<O>) {
        match self.state {
            ProtocolState::Closed => self
                .output_tx
                .send(Packet {
                    ty: PacketType::TerminateAck,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::Stopped => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.output_tx.send(Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                });

                let nak_require = self
                    .require
                    .iter()
                    .filter(|required| {
                        !packet
                            .options
                            .iter()
                            .any(|option| option.has_same_type(required))
                    })
                    .collect();

                let nak_deny_exact = self
                    .deny_exact
                    .iter()
                    .filter_map(|(denied, suggest)| {
                        if packet.options.iter().any(|&option| option == *denied) {
                            Some(suggest)
                        } else {
                            None
                        }
                    })
                    .collect();

                let reject_deny = self
                    .deny
                    .iter()
                    .filter(|denied| {
                        packet
                            .options
                            .iter()
                            .any(|option| option.has_same_type(denied))
                    })
                    .collect();

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    fn rca(&mut self, packet: Packet<O>) {}

    fn rcn(&mut self, packet: Packet<O>) {}

    fn rtr(&mut self, packet: Packet<O>) {}

    fn rta(&mut self, packet: Packet<O>) {}

    fn ruc(&mut self, packet: Packet<O>) {}

    fn rxj_positive(&mut self, packet: Packet<O>) {}

    fn rxj_negative(&mut self, packet: Packet<O>) {}

    fn is_acceptable(&self, options: &[O]) -> bool {
        // require, deny, deny_exact

        let require_satisfied = self
            .require
            .iter()
            .all(|required| options.iter().any(|option| option.has_same_type(required)));

        let deny_satisfied = self
            .deny
            .iter()
            .all(|denied| !options.iter().any(|option| option.has_same_type(denied)));

        let deny_exact_satisfied = self
            .deny_exact
            .iter()
            .all(|(denied, _)| !options.iter().any(|&option| option == *denied));

        require_satisfied && deny_satisfied && deny_exact_satisfied
    }

    fn need_code(&self, code: &PacketType) -> bool {
        match code {
            PacketType::ConfigureRequest
            | PacketType::ConfigureAck
            | PacketType::ConfigureNak
            | PacketType::ConfigureReject
            | PacketType::TerminateRequest
            | PacketType::TerminateAck
            | PacketType::CodeReject => true,
            PacketType::ProtocolReject => self.need_protocol_reject,
            PacketType::Unknown => false,
        }
    }

    fn need_protocol(protocol: u16) -> bool {
        use ppproperly::ppp;

        protocol == ppp::LCP // TODO: Or the agreed-upon auth protocol of either peer.
    }
}
