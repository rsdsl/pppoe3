//! Utilities for handling PPPoE Discovery state.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Interval;

/// The PPPoE client state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PppoeClientState {
    #[default]
    Closed, // No Open has occured, no restart timer
    InitiationSent, // PADI sent, Open initiated, restart timer running
    RequestSent,    // PADR sent, restart timer running
    Active,         // PADS received, no restart timer; session is active
}

/// List of valid types for `PppoePacket`s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PppoeType {
    Padi,
    Pado,
    Padr,
    Pads,
    Padt,
}

/// A packet that can be a PADI, PADO, PADR, PADS or PADT.
#[derive(Debug)]
pub struct PppoePacket {
    pub ty: PppoeType,
    pub ac_cookie: Option<Vec<u8>>,
}

/// A PPPoE client implementation as per RFC 2516.
#[derive(Debug)]
pub struct PppoeClient {
    ac_cookie: Option<Vec<u8>>, // mutated during discovery

    state: PppoeClientState,

    restart_timer: Interval,
    restart_counter: i32,

    max_request: i32,

    output_tx: mpsc::UnboundedSender<PppoePacket>,
    output_rx: mpsc::UnboundedReceiver<PppoePacket>,

    upper_status_tx: watch::Sender<bool>,
    upper_status_rx: watch::Receiver<bool>,
}

impl PppoeClient {
    /// Creates a new `PppoeClient`.
    ///
    /// You must start calling the [`PppoeClient::to_send`] method
    /// before calling the [`PppoeClient::open`] method
    /// and keep calling it until [`PppoeClient::close`] has been issued.
    ///
    /// # Arguments
    ///
    /// * `restart_interval` - The retransmission interval, default is 3 seconds.
    /// * `max_request` - The maximum number of PADRs to retransmit, default is 10.
    pub fn new(restart_interval: Option<Duration>, max_request: Option<i32>) -> Self {
        let restart_timer =
            tokio::time::interval(restart_interval.unwrap_or(Duration::from_secs(3)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (upper_status_tx, upper_status_rx) = watch::channel(false);

        Self {
            ac_cookie: None,

            state: PppoeClientState::default(),

            restart_timer,
            restart_counter: 0,

            max_request: max_request.unwrap_or(10),

            output_tx,
            output_rx,

            upper_status_tx,
            upper_status_rx,
        }
    }

    /// Waits for and returns the next packet to send.
    pub async fn to_send(&mut self) -> PppoePacket {
        loop {
            tokio::select! {
                packet = self.output_rx.recv() => return packet.expect("output channel is closed"),
                _ = self.restart_timer.tick() => if self.restart_counter != 0 {
                    if let Some(packet) = self.timeout_positive() { return packet; }
                } else {
                    self.timeout_negative();
                }
            }
        }
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RPO, RPS or RPT events.
    pub fn from_recv(&mut self, packet: PppoePacket) {
        match packet.ty {
            PppoeType::Padi | PppoeType::Padr => {} // illegal
            PppoeType::Pado => self.rpo(packet),
            PppoeType::Pads => self.rps(),
            PppoeType::Padt => self.rpt(),
        }
    }

    /// Issues an administrative open, allowing the protocol to start discovery.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {
        match self.state {
            PppoeClientState::Closed => {
                self.restart_timer.reset();
                self.restart_counter = -1;

                self.output_tx
                    .send(PppoePacket {
                        ty: PppoeType::Padi,
                        ac_cookie: None,
                    })
                    .expect("output channel is closed");

                self.state = PppoeClientState::InitiationSent;
            }
            PppoeClientState::InitiationSent
            | PppoeClientState::RequestSent
            | PppoeClientState::Active => {} // illegal
        }
    }

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {
        match self.state {
            PppoeClientState::Closed => {} // illegal
            PppoeClientState::InitiationSent | PppoeClientState::RequestSent => {
                self.state = PppoeClientState::Closed
            }
            PppoeClientState::Active => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.output_tx
                    .send(PppoePacket {
                        ty: PppoeType::Padt,
                        ac_cookie: None,
                    })
                    .expect("output channel is closed");

                self.state = PppoeClientState::Closed;
            }
        }
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `PppoeClient` is in the `Active` state and available for
    /// upper layers to use.
    pub fn active(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    fn timeout_positive(&mut self) -> Option<PppoePacket> {
        match self.state {
            PppoeClientState::Closed | PppoeClientState::Active => None, // illegal
            PppoeClientState::InitiationSent => Some(PppoePacket {
                ty: PppoeType::Padi,
                ac_cookie: None,
            }),
            PppoeClientState::RequestSent => {
                self.restart_counter -= 1;
                Some(PppoePacket {
                    ty: PppoeType::Padr,
                    ac_cookie: self.ac_cookie.clone(),
                })
            }
        }
    }

    fn timeout_negative(&mut self) {
        match self.state {
            PppoeClientState::Closed
            | PppoeClientState::InitiationSent
            | PppoeClientState::Active => {} // illegal
            PppoeClientState::RequestSent => {
                self.output_tx
                    .send(PppoePacket {
                        ty: PppoeType::Padi,
                        ac_cookie: None,
                    })
                    .expect("output channel is closed");

                self.state = PppoeClientState::InitiationSent;
            }
        }
    }

    fn rpo(&mut self, packet: PppoePacket) {
        match self.state {
            PppoeClientState::Closed | PppoeClientState::RequestSent | PppoeClientState::Active => {
            } // illegal
            PppoeClientState::InitiationSent => {
                self.restart_timer.reset();
                self.restart_counter = self.max_request;

                self.ac_cookie = packet.ac_cookie;

                self.output_tx
                    .send(PppoePacket {
                        ty: PppoeType::Padr,
                        ac_cookie: self.ac_cookie.clone(),
                    })
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = PppoeClientState::RequestSent;
            }
        }
    }

    fn rps(&mut self) {
        match self.state {
            PppoeClientState::Closed
            | PppoeClientState::InitiationSent
            | PppoeClientState::Active => {} // illegal
            PppoeClientState::RequestSent => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.state = PppoeClientState::Active;
            }
        }
    }

    fn rpt(&mut self) {
        match self.state {
            PppoeClientState::Closed
            | PppoeClientState::InitiationSent
            | PppoeClientState::RequestSent => {} // illegal
            PppoeClientState::Active => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.restart_timer.reset();

                self.output_tx
                    .send(PppoePacket {
                        ty: PppoeType::Padi,
                        ac_cookie: None,
                    })
                    .expect("output channel is closed");

                self.state = PppoeClientState::InitiationSent;
            }
        }
    }
}
