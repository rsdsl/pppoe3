use crate::ProtocolOption;

use ppproperly::LcpOpt;

impl ProtocolOption for LcpOpt {
    const PROTOCOL: u16 = ppproperly::LCP;

    fn is_unknown(&self) -> bool {
        matches!(self, LcpOpt::Unhandled(..))
    }
}
