use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Interval;

/// The CHAP peer state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ChapClientState {
    #[default]
    Initial, // Lower layer down, no Open has occured, no timeout
    Starting,     // Lower layer down, Open initiated, no timeout
    Closed,       // Lower layer up, no Open has occured, no timeout
    Stopped,      // Lower layer up, Open initiated, no timeout
    Waiting,      // No Challenge received, timeout running
    ResponseSent, // Response sent, no reply, timeout running
    ReauthSent,   // Second Challenge received, Response sent, no reply, timeout running
    Failed,       // Response sent, Failure received, no timeout; link is to be terminated
    Opened,       // Response sent, Success received, no timeout; auth is successful
}

/// List of valid packet types for `ChapPacket`s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChapType {
    Challenge,
    Response,
    Success,
    Failure,
    TerminateLower,
}

/// A packet that can be a Challenge, Response, Success, Failure
/// or a signal to terminate the link.
#[derive(Debug)]
pub struct ChapPacket {
    pub ty: ChapType,
    pub id: u8,
    pub data: Vec<u8>,
}

/// The Challenge-Handshake Authentication Protocol peer implementation
/// as per RFC 1994.
#[derive(Debug)]
pub struct ChapClient {
    state: ChapClientState,

    timeout: Interval,

    output_tx: mpsc::UnboundedSender<ChapPacket>,
    output_rx: mpsc::UnboundedReceiver<ChapPacket>,

    upper_status_tx: watch::Sender<bool>,
    upper_status_rx: watch::Receiver<bool>,
}

impl ChapClient {
    /// Creates a new `ChapClient`.
    ///
    /// You must start calling the [`ChapClient::to_send`] method
    /// before calling the [`ChapClient::up`] method
    /// and keep calling it until [`ChapClient::close`] and [`ChapClient::down`]
    /// have been issued.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout for receiving Challenges, default is 30 seconds.
    pub fn new(timeout: Option<Duration>) -> Self {
        let timeout = tokio::time::interval(timeout.unwrap_or(Duration::from_secs(30)));
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (upper_status_tx, upper_status_rx) = watch::channel(false);

        Self {
            state: ChapClientState::default(),

            timeout,

            output_tx,
            output_rx,

            upper_status_tx,
            upper_status_rx,
        }
    }

    /// Waits for and returns the next packet to send.
    pub async fn to_send(&mut self) -> ChapPacket {
        tokio::select! {
        packet = self.output_rx.recv() => packet.expect("output channel is closed"),
        _ = self.timeout.tick() => self.fail(),
            }
    }

    /// Feeds a packet into the state machine for processing.
    /// Can trigger the RC, RS or RF events.
    pub fn from_recv(&mut self, packet: ChapPacket) {
        match packet.ty {
            ChapType::Challenge => self.rc(packet),
            ChapType::Response | ChapType::TerminateLower => {} // illegal
            ChapType::Success => self.rs(),
            ChapType::Failure => self.rf(),
        }
    }

    /// Signals to the state machine that the lower layer is now up.
    /// This is equivalent to the Up event.
    pub fn up(&mut self) {
        match self.state {
            ChapClientState::Initial => self.state = ChapClientState::Closed,
            ChapClientState::Starting => {
                self.timeout.reset();
                self.state = ChapClientState::Waiting;
            }
            ChapClientState::Closed
            | ChapClientState::Stopped
            | ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent
            | ChapClientState::Failed
            | ChapClientState::Opened => {} // illegal
        }
    }

    /// Signals to the state machine that the lower layer is now down.
    /// This is equivalent to the Down event.
    pub fn down(&mut self) {
        match self.state {
            ChapClientState::Initial | ChapClientState::Starting => {} // illegal
            ChapClientState::Closed => self.state = ChapClientState::Initial,
            ChapClientState::Stopped
            | ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent
            | ChapClientState::Failed => self.state = ChapClientState::Starting,
            ChapClientState::Opened => {
                self.upper_status_tx
                    .send(false)
                    .expect("upper status channel is closed");

                self.state = ChapClientState::Starting;
            }
        }
    }

    /// Issues an administrative open, allowing the protocol to start authentication.
    /// This is equivalent to the Open event.
    pub fn open(&mut self) {
        match self.state {
            ChapClientState::Initial => self.state = ChapClientState::Starting,
            ChapClientState::Starting
            | ChapClientState::Stopped
            | ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent
            | ChapClientState::Failed
            | ChapClientState::Opened => {}
            ChapClientState::Closed => {
                self.timeout.reset();
                self.state = ChapClientState::Waiting;
            }
        }
    }

    /// Issues an administrative close, gracefully shutting down the protocol.
    /// This is equivalent to the Close event.
    pub fn close(&mut self) {
        match self.state {
            ChapClientState::Initial | ChapClientState::Closed => {} // illegal
            ChapClientState::Starting => self.state = ChapClientState::Initial,
            ChapClientState::Stopped
            | ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent
            | ChapClientState::Failed
            | ChapClientState::Opened => self.state = ChapClientState::Closed,
        }
    }

    /// Returns a watch channel receiver that can be used to monitor whether
    /// the `ChapClient` is in the `Opened` state.
    pub fn opened(&self) -> watch::Receiver<bool> {
        self.upper_status_rx.clone()
    }

    fn fail(&mut self) -> ChapPacket {
        self.state = ChapClientState::Failed;

        ChapPacket {
            ty: ChapType::TerminateLower,
            id: 0,
            data: Vec::default(),
        }
    }

    fn rc(&mut self, packet: ChapPacket) {
        match self.state {
            ChapClientState::Initial | ChapClientState::Starting => {} // illegal
            ChapClientState::Closed | ChapClientState::Stopped | ChapClientState::Failed => {}
            ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent => {
                self.output_tx
                    .send(ChapPacket {
                        ty: ChapType::Response,
                        id: packet.id,
                        data: packet.data,
                    })
                    .expect("output channel is closed");

                self.state = ChapClientState::ResponseSent;
            }
            ChapClientState::Opened => {
                self.output_tx
                    .send(ChapPacket {
                        ty: ChapType::Response,
                        id: packet.id,
                        data: packet.data,
                    })
                    .expect("output channel is closed");

                self.state = ChapClientState::ReauthSent;
            }
        }
    }

    fn rs(&mut self) {
        match self.state {
            ChapClientState::Initial | ChapClientState::Starting => {} // illegal
            ChapClientState::Closed
            | ChapClientState::Stopped
            | ChapClientState::Failed
            | ChapClientState::Opened => {}
            ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent => {
                self.upper_status_tx
                    .send(true)
                    .expect("upper status channel is closed");

                self.state = ChapClientState::Opened;
            }
        }
    }

    fn rf(&mut self) {
        match self.state {
            ChapClientState::Initial | ChapClientState::Starting => {} // illegal
            ChapClientState::Closed | ChapClientState::Stopped | ChapClientState::Failed => {}
            ChapClientState::Waiting
            | ChapClientState::ResponseSent
            | ChapClientState::ReauthSent
            | ChapClientState::Opened => {
                self.upper_status_tx.send_if_modified(|value| {
                    let ret = *value;
                    *value = false;
                    ret
                });

                let terminate_lower = self.fail();
                self.output_tx
                    .send(terminate_lower)
                    .expect("output channel is closed");
            }
        }
    }
}
