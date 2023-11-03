use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Interval;

/// The PAP peer state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PapClientState {
    #[default]
    Initial, // Lower layer down, no Open has occured, no restart timer
    Starting,    // Lower layer down, Open initiated, no restart timer; Up triggers Auth-Req
    Closed,      // Lower layer up, no Open has occured, no restart timer
    Stopped,     // Lower layer up, Open initiated, no restart_timer
    RequestSent, // Auth-Req sent, no reply, restart timer running
    Failed,      // Auth-Req sent, Auth-Nak received, no restart timer; link is to be terminated
    Opened,      // Auth-Req sent, Auth-Ack received, no restart timer; auth is completed
}

/// A packet that can be an Authenticate-Request, Authenticate-Ack, Authenticate-Nak
/// or a signal to terminate the link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PapPacket {
    AuthenticateRequest,
    AuthenticateAck,
    AuthenticateNak,
    TerminateLower,
}

/// The Password Authentication Protocol peer implementation
/// as per RFC 1334 section 2.
#[derive(Debug)]
pub struct PapClient {
    state: PapClientState,

    restart_timer: Interval,
    restart_counter: u32,

    max_request: u32,

    output_tx: mpsc::UnboundedSender<PapPacket>,
    output_rx: mpsc::UnboundedReceiver<PapPacket>,

    upper_status_tx: watch::Sender<bool>,
    upper_status_rx: watch::Receiver<bool>,
}

impl PapClient {
    /// Creates a new `PapClient`.
    ///
    /// You must start calling the [`PapClient::to_send`] method
    /// before calling the [`PapClient::up`] method
    /// and keep calling it until [`PapClient::close`] and [`PapClient::down`]
    /// have been issued.
    ///
    /// # Arguments
    ///
    /// * `restart_interval` - The retransmission interval, default is 3 seconds.
    /// * `max_request` - The maximum number of Authenticate-Requests to retransmit, default is 10.
    pub fn new(restart_interval: Option<Duration>, max_request: Option<u32>) -> Self {
        let restart_timer =
            tokio::time::interval(restart_interval.unwrap_or(Duration::from_secs(3)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (upper_status_tx, upper_status_rx) = watch::channel(false);

        Self {
            state: PapClientState::default(),

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
    pub async fn to_send(&mut self) -> PapPacket {
        tokio::select! {
            packet = self.output_rx.recv() => packet.expect("output channel is closed"),
            _ = self.restart_timer.tick() => if self.restart_counter > 0 {
                self.timeout_positive()
            } else {
                self.timeout_negative()
            }
        }
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RAA or RAN events.
    pub fn from_recv(&mut self, packet: PapPacket) {
        match packet {
            PapPacket::AuthenticateRequest | PapPacket::TerminateLower => {
                panic!("illegal state transition")
            }
            PapPacket::AuthenticateAck => self.raa(),
            PapPacket::AuthenticateNak => self.ran(),
        }
    }

    /// Signals to the state machine that the lower layer is now up.
    /// This is equivalent to the Up event.
    pub fn up(&mut self) {
        match self.state {
            PapClientState::Initial => self.state = PapClientState::Closed,
            PapClientState::Starting => {
                self.restart_timer.reset();
                self.restart_counter = self.max_request;

                self.output_tx
                    .send(PapPacket::AuthenticateRequest)
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = PapClientState::RequestSent;
            }
            PapClientState::Closed
            | PapClientState::Stopped
            | PapClientState::RequestSent
            | PapClientState::Failed
            | PapClientState::Opened => panic!("illegal state transition"),
        }
    }

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {
        match self.state {
            PapClientState::Initial | PapClientState::Starting => {
                panic!("illegal state transition")
            }
            PapClientState::Closed => self.state = PapClientState::Initial,
            PapClientState::Stopped => self.state = PapClientState::Starting,
            PapClientState::RequestSent => self.state = PapClientState::Starting,
            PapClientState::Failed => self.state = PapClientState::Starting,
            PapClientState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");
                self.state = PapClientState::Starting;
            }
        }
    }

    /// Issues an administrative open, allowing the protocol to start authentication.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {
        match self.state {
            PapClientState::Initial => self.state = PapClientState::Starting,
            PapClientState::Starting => {}
            PapClientState::Closed => {
                self.restart_timer.reset();
                self.restart_counter = self.max_request;

                self.output_tx
                    .send(PapPacket::AuthenticateRequest)
                    .expect("output channel is closed");
                self.restart_counter -= 1;

                self.state = PapClientState::RequestSent;
            }
            PapClientState::Stopped => {}
            PapClientState::RequestSent | PapClientState::Failed | PapClientState::Opened => {}
        }
    }

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {
        match self.state {
            PapClientState::Initial | PapClientState::Closed => panic!("illegal state transition"),
            PapClientState::Starting => self.state = PapClientState::Initial,
            PapClientState::Stopped
            | PapClientState::RequestSent
            | PapClientState::Failed
            | PapClientState::Opened => self.state = PapClientState::Closed,
        }
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `PapClient` is in the `Opened` state.
    pub fn opened(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    fn timeout_positive(&mut self) -> PapPacket {
        match self.state {
            PapClientState::Initial
            | PapClientState::Starting
            | PapClientState::Closed
            | PapClientState::Stopped
            | PapClientState::Failed
            | PapClientState::Opened => panic!("illegal state transition"),
            PapClientState::RequestSent => {
                self.restart_counter -= 1;
                PapPacket::AuthenticateRequest
            }
        }
    }

    fn timeout_negative(&mut self) -> PapPacket {
        match self.state {
            PapClientState::Initial
            | PapClientState::Starting
            | PapClientState::Closed
            | PapClientState::Stopped
            | PapClientState::Failed
            | PapClientState::Opened => panic!("illegal state transition"),
            PapClientState::RequestSent => {
                self.state = PapClientState::Failed;
                PapPacket::TerminateLower
            }
        }
    }

    fn raa(&mut self) {
        match self.state {
            PapClientState::Initial | PapClientState::Starting => {
                panic!("illegal state transition")
            }
            PapClientState::Closed
            | PapClientState::Stopped
            | PapClientState::Failed
            | PapClientState::Opened => {}
            PapClientState::RequestSent => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.state = PapClientState::Opened;
            }
        }
    }

    fn ran(&mut self) {
        match self.state {
            PapClientState::Initial | PapClientState::Starting => {
                panic!("illegal state transition")
            }
            PapClientState::Closed | PapClientState::Stopped | PapClientState::Failed => {}
            PapClientState::RequestSent | PapClientState::Opened => {
                self.output_tx
                    .send(PapPacket::TerminateLower)
                    .expect("output channel is closed");

                self.state = PapClientState::Failed;
            }
        }
    }
}
