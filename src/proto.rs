use std::mem;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Interval;

use ppproperly::{LcpOpt, Serialize};

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
pub trait ProtocolOption: Clone + Eq {
    const PROTOCOL: u16;

    fn has_same_type(&self, other: &Self) -> bool {
        mem::discriminant(self) == mem::discriminant(other)
    }
}

trait ProtocolOptionNeedProtocol {
    fn need_protocol(&self, protocol: u16) -> bool;
}

trait LcpOptNeedProtocol {
    fn need_protocol(&self, protocol: u16) -> bool;
}

/// A set of configuration parameters for a protocol.
#[derive(Debug)]
pub struct ProtocolConfig<O: ProtocolOption> {
    /// Options to require the peer to set including a suggestion.
    pub require: Vec<O>,
    /// Options not to accept under any circumstances.
    pub deny: Vec<O>,
    /// Options not to accept if they have one of the listed values including a suggestion.
    pub deny_exact: Vec<(O, O)>,

    /// Options to request initially.
    pub request: Vec<O>,
    /// Options not to accept suggestions for under any circumstances.
    pub refuse: Vec<O>,
    /// Options not to accept the listed suggestion values for.
    pub refuse_exact: Vec<O>,

    /// Whether this protocol makes use of the Protocol-Reject packet.
    pub need_protocol_reject: bool,

    /// The retransmission interval (Restart Timer), default is 3 seconds.
    pub restart_interval: Option<Duration>,
    /// The maximum number of Terminate-Requests to retransmit, default is 2.
    pub max_terminate: Option<u32>,
    /// The maximum number of Configure-Requests to retransmit, default is 10.
    pub max_configure: Option<u32>,
    /// The maximum number of Configure-Naks to send before switching to Configure-Rejects,
    /// default is 5.
    pub max_failure: Option<u32>,
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

    failure: u32,

    output_tx: mpsc::UnboundedSender<Packet<O>>,
    output_rx: mpsc::UnboundedReceiver<Packet<O>>,

    upper_status_tx: watch::Sender<bool>,
    upper_status_rx: watch::Receiver<bool>,
}

impl<O: ProtocolOption> NegotiationProtocol<O> {
    /// Creates a new `NegotiationProtocol`
    /// with the characteristics described by the [`ProtocolConfig`].
    ///
    /// You must start calling the [`NegotiationProtocol::to_send`] method
    /// before calling the [`NegotiationProtocol::up`] or [`NegotiationProtocol::open`] methods
    /// and keep calling it until [`NegotiationProtocol::close`] and [`NegotiationProtocol::down`]
    /// have been issued.
    pub fn new(config: ProtocolConfig<O>) -> Self {
        let ProtocolConfig {
            require,
            deny,
            deny_exact,
            request,
            refuse,
            refuse_exact,
            need_protocol_reject,
            restart_interval,
            max_terminate,
            max_configure,
            max_failure,
        } = config;

        let restart_timer =
            tokio::time::interval(restart_interval.unwrap_or(Duration::from_secs(3)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (upper_status_tx, upper_status_rx) = watch::channel(false);

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

            failure: 0,

            output_tx,
            output_rx,

            upper_status_tx,
            upper_status_rx,
        }
    }

    /// Waits for and returns the next packet to send.
    pub async fn to_send(&mut self) -> Packet<O> {
        loop {
            tokio::select! {
                packet = self.output_rx.recv() => return packet.expect("output channel is closed"),
                _ = self.restart_timer.tick() => if self.restart_counter > 0 { // TO+ event
                    return self.timeout_positive();
                } else { // TO- event
                    self.timeout_negative();
                }
            }
        }
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
                if (&*self).need_protocol(packet.rejected_protocol) {
                    self.rxj_negative(packet)
                } else {
                    self.rxj_positive(packet)
                }
            }
            PacketType::EchoRequest => {
                self.output_tx
                    .send(Packet {
                        ty: PacketType::EchoReply,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
            }
            PacketType::EchoReply | PacketType::DiscardRequest => {}
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

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Closed
            | ProtocolState::Stopped
            | ProtocolState::Closing
            | ProtocolState::Stopping
            | ProtocolState::RequestSent
            | ProtocolState::AckReceived
            | ProtocolState::AckSent
            | ProtocolState::Opened => panic!("illegal state transition"),
        }
    }

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed => self.state = ProtocolState::Initial,
            ProtocolState::Stopped => self.state = ProtocolState::Starting, // tls action
            ProtocolState::Closing => self.state = ProtocolState::Initial,
            ProtocolState::Stopping => self.state = ProtocolState::Starting,
            ProtocolState::RequestSent => self.state = ProtocolState::Starting,
            ProtocolState::AckReceived => self.state = ProtocolState::Starting,
            ProtocolState::AckSent => self.state = ProtocolState::Starting,
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.state = ProtocolState::Starting;
            }
        }
    }

    /// Issues an administrative open, allowing the protocol to start negotiation.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {
        // The [r] (restart) implementation option is not implemented.
        match self.state {
            ProtocolState::Initial => self.state = ProtocolState::Starting, // tls action
            ProtocolState::Starting => {}
            ProtocolState::Closed => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Stopped => {}
            ProtocolState::Closing => self.state = ProtocolState::Stopping,
            ProtocolState::Stopping
            | ProtocolState::RequestSent
            | ProtocolState::AckReceived
            | ProtocolState::AckSent
            | ProtocolState::Opened => {}
        }
    }

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {
        match self.state {
            ProtocolState::Initial => {}
            ProtocolState::Starting => self.state = ProtocolState::Initial, // tlf action
            ProtocolState::Closed => {}
            ProtocolState::Stopped => self.state = ProtocolState::Closed,
            ProtocolState::Closing => {}
            ProtocolState::Stopping => self.state = ProtocolState::Closing,
            ProtocolState::RequestSent | ProtocolState::AckReceived | ProtocolState::AckSent => {
                self.restart_timer.reset();
                self.restart_counter = self.max_terminate;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::TerminateRequest,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::Closing;
            }
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();
                self.restart_counter = self.max_terminate;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::TerminateRequest,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::Closing;
            }
        }
    }

    /// Reports whether the `NegotiationProtocol` is in the `Closed` state.
    pub fn is_closed(&self) -> bool {
        self.state == ProtocolState::Closed
    }

    /// Reports whether the `NegotiationProtocol` is in the `Stopped` state.
    pub fn is_stopped(&self) -> bool {
        self.state == ProtocolState::Stopped
    }

    /// Reports whether the `NegotiationProtocol` is in an involuntary closed state.
    pub fn is_shut_down(&self) -> bool {
        self.is_closed() || self.is_stopped()
    }

    /// Returns the options set by the peer.
    pub fn peer(&self) -> &[O] {
        &self.peer
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `NegotiationProtocol` is in the `Opened` state.
    pub fn opened(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    fn timeout_positive(&mut self) -> Packet<O> {
        match self.state {
            ProtocolState::Initial
            | ProtocolState::Starting
            | ProtocolState::Closed
            | ProtocolState::Stopped
            | ProtocolState::Opened => panic!("illegal state transition"),
            ProtocolState::Closing | ProtocolState::Stopping => {
                self.restart_counter -= 1;

                Packet {
                    ty: PacketType::TerminateRequest,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                }
            }
            ProtocolState::RequestSent | ProtocolState::AckSent => {
                self.restart_counter -= 1;

                Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                }
            }
            ProtocolState::AckReceived => {
                self.restart_counter -= 1;
                self.state = ProtocolState::RequestSent;

                Packet {
                    ty: PacketType::ConfigureRequest,
                    options: self.request.clone(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                }
            }
        }
    }

    fn timeout_negative(&mut self) {
        match self.state {
            ProtocolState::Initial
            | ProtocolState::Starting
            | ProtocolState::Closed
            | ProtocolState::Stopped
            | ProtocolState::Opened => panic!("illegal state transition"),
            ProtocolState::Closing => self.state = ProtocolState::Closed, // tlf action
            ProtocolState::Stopping => self.state = ProtocolState::Stopped, // tlf action
            ProtocolState::RequestSent | ProtocolState::AckReceived | ProtocolState::AckSent => {
                self.state = ProtocolState::Stopped
            } // tlf action
        }
    }

    fn rcr_positive(&mut self, packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
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

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureAck,
                        options: packet.options.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

                self.peer = packet.options;
                self.failure = 0;

                self.state = ProtocolState::AckSent;
            }
            ProtocolState::Closing | ProtocolState::Stopping => {}
            ProtocolState::RequestSent => {
                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureAck,
                        options: packet.options.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

                self.peer = packet.options;
                self.failure = 0;

                self.state = ProtocolState::AckSent;
            }
            ProtocolState::AckReceived => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureAck,
                        options: packet.options,
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

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
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureAck,
                        options: packet.options.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

                self.peer = packet.options;
                self.failure = 0;

                self.state = ProtocolState::AckSent;
            }
        }
    }

    fn rcr_negative(&mut self, packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
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

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                let response = self.configure_nak_or_reject_from_request(packet);
                self.output_tx
                    .send(response)
                    .expect("output channel is closed");

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Closing | ProtocolState::Stopping => {}
            ProtocolState::RequestSent => {
                let response = self.configure_nak_or_reject_from_request(packet);
                self.output_tx
                    .send(response)
                    .expect("output channel is closed");
            }
            ProtocolState::AckReceived => {
                let response = self.configure_nak_or_reject_from_request(packet);
                self.output_tx
                    .send(response)
                    .expect("output channel is closed");
            }
            ProtocolState::AckSent => {
                let response = self.configure_nak_or_reject_from_request(packet);
                self.output_tx
                    .send(response)
                    .expect("output channel is closed");

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                let response = self.configure_nak_or_reject_from_request(packet);
                self.output_tx
                    .send(response)
                    .expect("output channel is closed");

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    fn rca(&mut self, _packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed | ProtocolState::Stopped => self
                .output_tx
                .send(Packet {
                    ty: PacketType::TerminateAck,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::Closing | ProtocolState::Stopping => {}
            ProtocolState::RequestSent => {
                self.restart_counter = self.max_configure;
                self.state = ProtocolState::AckReceived;
            }
            ProtocolState::AckReceived => {
                self.restart_timer.reset();

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::AckSent => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.restart_counter = self.max_configure;
                self.state = ProtocolState::Opened;
            }
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    fn rcn(&mut self, packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed | ProtocolState::Stopped => self
                .output_tx
                .send(Packet {
                    ty: PacketType::TerminateAck,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::Closing | ProtocolState::Stopping => {}
            ProtocolState::RequestSent => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.process_configure_nak_or_reject(packet);

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;
            }
            ProtocolState::AckReceived => {
                self.restart_timer.reset();

                self.process_configure_nak_or_reject(packet);

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::AckSent => {
                self.restart_timer.reset();
                self.restart_counter = self.max_configure;

                self.process_configure_nak_or_reject(packet);

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;
            }
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.process_configure_nak_or_reject(packet);

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    fn rtr(&mut self, _packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed
            | ProtocolState::Stopped
            | ProtocolState::Closing
            | ProtocolState::Stopping
            | ProtocolState::RequestSent => self
                .output_tx
                .send(Packet {
                    ty: PacketType::TerminateAck,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: 0,
                })
                .expect("output channel is closed"),
            ProtocolState::AckReceived | ProtocolState::AckSent => {
                self.output_tx
                    .send(Packet {
                        ty: PacketType::TerminateAck,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

                self.state = ProtocolState::RequestSent;
            }
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_counter = 0;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::TerminateAck,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");

                self.state = ProtocolState::Stopping;
            }
        }
    }

    fn rta(&mut self, _packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed | ProtocolState::Stopped => {}
            ProtocolState::Closing => self.state = ProtocolState::Closed, // tlf action
            ProtocolState::Stopping => self.state = ProtocolState::Stopped, // tlf action
            ProtocolState::RequestSent => {}
            ProtocolState::AckReceived => self.state = ProtocolState::RequestSent,
            ProtocolState::AckSent => {}
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.output_tx
                    .send(Packet {
                        ty: PacketType::ConfigureRequest,
                        options: self.request.clone(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::RequestSent;
            }
        }
    }

    fn ruc(&mut self, packet: Packet<O>) {
        self.output_tx
            .send(Packet {
                ty: PacketType::CodeReject,
                options: Vec::default(),
                rejected_code: packet.rejected_code,
                rejected_protocol: 0,
            })
            .expect("output channel is closed");
    }

    fn rxj_positive(&mut self, _packet: Packet<O>) {
        if self.state == ProtocolState::AckReceived {
            self.state = ProtocolState::RequestSent;
        }
    }

    fn rxj_negative(&mut self, _packet: Packet<O>) {
        match self.state {
            ProtocolState::Initial | ProtocolState::Starting => panic!("illegal state transition"),
            ProtocolState::Closed | ProtocolState::Stopped => {} // tlf action
            ProtocolState::Closing => self.state = ProtocolState::Closed, // tlf action
            ProtocolState::Stopping
            | ProtocolState::RequestSent
            | ProtocolState::AckReceived
            | ProtocolState::AckSent => self.state = ProtocolState::Stopped, // tlf action
            ProtocolState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();
                self.restart_counter = self.max_terminate;

                self.output_tx
                    .send(Packet {
                        ty: PacketType::TerminateRequest,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: 0,
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = ProtocolState::Stopping;
            }
        }
    }

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
            .all(|(denied, _)| !options.iter().any(|option| *option == *denied));

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
            PacketType::EchoRequest
            | PacketType::EchoReply
            | PacketType::DiscardRequest
            | PacketType::Unknown => false,
        }
    }

    fn configure_nak_or_reject_from_request(&mut self, packet: Packet<O>) -> Packet<O> {
        let mut nak_deny_exact: Vec<O> = self
            .deny_exact
            .iter()
            .cloned()
            .filter_map(|(denied, suggest)| {
                if let Some(option) = packet.options.iter().find(|&option| *option == denied) {
                    Some(if self.failure < self.max_failure {
                        suggest
                    } else {
                        option.clone()
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut nak_require: Vec<O> = self
            .require
            .iter()
            .cloned()
            .filter(|required| {
                !packet
                    .options
                    .iter()
                    .any(|option| option.has_same_type(required))
            })
            .collect();

        if self.failure < self.max_failure {
            nak_deny_exact.append(&mut nak_require)
        };
        let nak = nak_deny_exact;

        let reject_deny = self
            .deny
            .iter()
            .cloned()
            .filter(|denied| {
                packet
                    .options
                    .iter()
                    .any(|option| option.has_same_type(denied))
            })
            .collect();

        let reject = reject_deny;

        if !nak.is_empty() {
            Packet {
                ty: if self.failure < self.max_failure {
                    PacketType::ConfigureNak
                } else {
                    PacketType::ConfigureReject
                },
                options: nak,
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }
        } else {
            // No check, this function is only called if something is inacceptable.
            Packet {
                ty: PacketType::ConfigureReject,
                options: reject,
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }
        }
    }

    fn process_configure_nak_or_reject(&mut self, packet: Packet<O>) {
        let mut accepted_naks = packet.options.iter().filter(|&option| {
            !self
                .refuse
                .iter()
                .any(|refused| refused.has_same_type(option))
                && !self.refuse_exact.iter().any(|refused| *refused == *option)
        });

        match packet.ty {
                    PacketType::ConfigureNak => {
                        for option in self.request.iter_mut() {
                            if let Some(nak) = accepted_naks.find(|nak| nak.has_same_type(option)) {
                                *option = nak.clone();
                            }
                        }
                    }
                    PacketType::ConfigureReject => self.request.retain(|option| {
                        !accepted_naks
                            .any(|nak| nak.has_same_type(option))
                    }),
                    _ => panic!("NegotiationProtocol::rcn called on packet type other than Configure-Nak or Configure-Reject"),
                }
    }
}

impl<O: ProtocolOption> ProtocolOptionNeedProtocol for &NegotiationProtocol<O> {
    fn need_protocol(&self, protocol: u16) -> bool {
        protocol == ppproperly::LCP || protocol == O::PROTOCOL
    }
}

impl LcpOptNeedProtocol for NegotiationProtocol<LcpOpt> {
    fn need_protocol(&self, protocol: u16) -> bool {
        let our_auth = self.request.iter().find_map(|option| {
            if let LcpOpt::AuthenticationProtocol(auth_protocol) = option {
                Some(auth_protocol)
            } else {
                None
            }
        });

        let peer_auth = self.peer().iter().find_map(|option| {
            if let LcpOpt::AuthenticationProtocol(auth_protocol) = option {
                Some(auth_protocol)
            } else {
                None
            }
        });

        let need_our = match our_auth {
            Some(auth_protocol) => {
                let mut buf = Vec::new();
                match auth_protocol.serialize(&mut buf) {
                    Ok(_) => u16::from_be_bytes(
                        buf[..2].try_into().unwrap_or(ppproperly::LCP.to_be_bytes()),
                    ),
                    Err(_) => ppproperly::LCP,
                }
            }
            None => ppproperly::LCP,
        };

        let need_peer = match peer_auth {
            Some(auth_protocol) => {
                let mut buf = Vec::new();
                match auth_protocol.serialize(&mut buf) {
                    Ok(_) => u16::from_be_bytes(
                        buf[..2].try_into().unwrap_or(ppproperly::LCP.to_be_bytes()),
                    ),
                    Err(_) => ppproperly::LCP,
                }
            }
            None => ppproperly::LCP,
        };

        protocol == ppproperly::LCP || protocol == need_our || protocol == need_peer
    }
}
