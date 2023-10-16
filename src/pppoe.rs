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

    pub fn is_closed(&self) -> bool {
        self.state() == PppoeState::Dead
    }

    pub fn state(&self) -> PppoeState {
        self.state
    }

    pub fn set_state(&mut self, state: PppoeState) {
        self.state = state;
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
