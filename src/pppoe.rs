use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use ppproperly::MacAddr;

#[derive(Debug, Eq, PartialEq)]
pub struct Pppoe {
    state: PppoeState,
    ac_mac: MacAddr,
    timestamp: Instant,
}

impl Pppoe {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            state: PppoeState::Dead,
            ac_mac: MacAddr::BROADCAST,
            timestamp: Instant::now(),
        }
    }

    pub fn closed(&self) -> Closed<'_> {
        Closed { pppoe: self }
    }
}

impl Default for Pppoe {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PppoeState {
    Dead,    // No session, no offers. The client may choose whether to send PADIs.
    Request, // No session, trying to request an offer. The client must send PADRs or time out.
    Active,  // PPP session established. Can be terminated by a remote PADT or upper layers.
}

#[derive(Debug)]
pub struct Closed<'a> {
    pppoe: &'a Pppoe,
}

impl<'a> Future for Closed<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Closed<'a>>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.pppoe.state == PppoeState::Dead {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
