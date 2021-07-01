use std::convert::{From, TryFrom};
use std::fmt;
use std::net::Ipv6Addr;

mod buffer;
pub mod options;
pub mod params;
#[cfg(test)]
mod test;

type Result<T> = std::result::Result<T, Error>;

#[derive(PartialEq)]
pub enum Error {
    UnknownMsgCode(u8),
    BadOption(String),
    Unimplemented(String),
    TooShort,
    Other(String),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::UnknownMsgCode(code) => format!("Unknown message code: '{}'", code),
                Error::BadOption(option) => format!("Bad option: '{}'", option),
                Error::Unimplemented(x) => format!("Unimplemented functionality: '{}'", x),
                Error::TooShort => "buffer too short".to_string(),
                Error::Other(x) => x.to_string(),
            }
        )
    }
}

// Ignore the warning because this is an asymmetric operation
#[allow(clippy::from_over_into)]
impl Into<Error> for String {
    fn into(self) -> Error {
        Error::Other(self)
    }
}

// Ignore the warning because this is an asymmetric operation
#[allow(clippy::from_over_into)]
impl Into<Error> for &str {
    fn into(self) -> Error {
        self.to_string().into()
    }
}

/// All of the DHCPv6 message types defined in rfc3315
#[derive(Copy, Clone, PartialEq)]
pub enum MsgType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl fmt::Debug for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MsgType::Solicit => "solicit",
                MsgType::Advertise => "advertise",
                MsgType::Request => "request",
                MsgType::Confirm => "confirm",
                MsgType::Renew => "renew",
                MsgType::Rebind => "rebind",
                MsgType::Reply => "reply",
                MsgType::Release => "release",
                MsgType::Decline => "decline",
                MsgType::Reconfigure => "reconfigure",
                MsgType::InformationRequest => "infoRequest",
                MsgType::RelayForw => "relayForw",
                MsgType::RelayRepl => "relayReply",
            }
        )
    }
}

impl TryFrom<u8> for MsgType {
    type Error = ();

    fn try_from(code: u8) -> std::result::Result<Self, Self::Error> {
        match code {
            1 => Ok(MsgType::Solicit),
            2 => Ok(MsgType::Advertise),
            3 => Ok(MsgType::Request),
            4 => Ok(MsgType::Confirm),
            5 => Ok(MsgType::Renew),
            6 => Ok(MsgType::Rebind),
            7 => Ok(MsgType::Reply),
            8 => Ok(MsgType::Release),
            9 => Ok(MsgType::Decline),
            10 => Ok(MsgType::Reconfigure),
            11 => Ok(MsgType::InformationRequest),
            12 => Ok(MsgType::RelayForw),
            13 => Ok(MsgType::RelayRepl),
            _ => Err(()),
        }
    }
}

impl From<MsgType> for u8 {
    fn from(msg: MsgType) -> u8 {
        msg as u8
    }
}

/// RFC-defined parameters governing how frequently, and for how long, a
/// message should be retransmitted before accepting that no one is listening.
pub struct RetransmitParams {
    pub irt: u32, // Initial retransmission time
    pub mrt: u32, // Maximum retransmission time
    pub mrc: u32, // Maximum retransmission count
    pub mrd: u32, // Maximum retransmission duration
}

/// Returns the appropriate retransmit parameters for the given message type.
/// None will be returned for messages that are not intended to be
/// retransmitted.
///
/// Note - the following message types have one or more dynamic parameters,
/// which depend on the state of the associated lease: MsgType::Renew,
/// MsgType::Rebind
pub fn retransmit_params(msg_type: MsgType) -> Option<RetransmitParams> {
    match msg_type {
        MsgType::Solicit => Some(RetransmitParams {
            irt: params::SOL_TIMEOUT,
            mrt: params::SOL_MAX_RT,
            mrc: 0,
            mrd: 0,
        }),
        MsgType::Request => Some(RetransmitParams {
            irt: params::REQ_TIMEOUT,
            mrt: params::REQ_MAX_RT,
            mrc: params::REQ_MAX_RC,
            mrd: 0,
        }),
        MsgType::Confirm => Some(RetransmitParams {
            irt: params::CNF_TIMEOUT,
            mrt: params::CNF_MAX_RT,
            mrc: 0,
            mrd: params::CNF_MAX_RD,
        }),
        MsgType::Renew => Some(RetransmitParams {
            irt: params::REN_TIMEOUT,
            mrt: params::REN_MAX_RT,
            mrc: 0,
            mrd: 0, // not fixed - it depends on T2
        }),
        MsgType::Rebind => Some(RetransmitParams {
            irt: params::REB_TIMEOUT,
            mrt: params::REB_MAX_RT,
            mrc: 0,
            mrd: 0, // not fixed - it depends on the remaining lifetimes
                    // of all addresses
        }),
        MsgType::Release => Some(RetransmitParams {
            irt: params::REL_TIMEOUT,
            mrt: 0,
            mrc: params::REL_MAX_RC,
            mrd: 0,
        }),
        MsgType::Decline => Some(RetransmitParams {
            irt: params::DEC_TIMEOUT,
            mrt: 0,
            mrc: params::DEC_MAX_RC,
            mrd: 0,
        }),
        MsgType::InformationRequest => Some(RetransmitParams {
            irt: params::INF_TIMEOUT,
            mrt: params::INF_MAX_RT,
            mrc: 0,
            mrd: 0,
        }),
        _ => None,
    }
}

/// All of the DHCPv6 status codes defined in rfc3315
#[derive(PartialEq, Clone, Copy)]
pub enum StatusCode {
    Success = 0,
    UnspecFail = 1,
    NoAddrsAvail = 2,
    NoBinding = 3,
    NotOnLink = 4,
    UseMulticast = 5,
}

impl TryFrom<u16> for StatusCode {
    type Error = ();

    fn try_from(code: u16) -> std::result::Result<Self, Self::Error> {
        match code {
            0 => Ok(StatusCode::Success),
            1 => Ok(StatusCode::UnspecFail),
            2 => Ok(StatusCode::NoAddrsAvail),
            3 => Ok(StatusCode::NoBinding),
            4 => Ok(StatusCode::NotOnLink),
            5 => Ok(StatusCode::UseMulticast),
            _ => Err(()),
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                StatusCode::Success => "Success",
                StatusCode::UnspecFail => "UnspecFail",
                StatusCode::NoAddrsAvail => "noAddrsAvail",
                StatusCode::NoBinding => "NoBinding",
                StatusCode::NotOnLink => "NotOnLink",
                StatusCode::UseMulticast => "UseMulticast",
            }
        )
    }
}

impl fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// Client-Server DHCPv6 message as defined in rfc3315, section 6.
#[derive(PartialEq)]
pub struct ClientMsg {
    pub msg_type: MsgType,
    pub tx_id: u32,
    pub options: Vec<options::Dhcpv6Option>,
}

/// Find the first option of the given type in the option list
pub fn find_one_option(
    list: &[options::Dhcpv6Option],
    opt_type: u16,
) -> Option<&options::Dhcpv6Option> {
    list.iter().find(|&o| opt_type == u16::from(o))
}

/// Find all options of the given type in the option list
pub fn find_all_options(
    list: &[options::Dhcpv6Option],
    opt_type: u16,
) -> Vec<&options::Dhcpv6Option> {
    list.iter().filter(|&o| opt_type == u16::from(o)).collect()
}

impl fmt::Debug for ClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "type: {:?}  txid: 0x{:x}  options: {:?}",
            self.msg_type, self.tx_id, self.options
        )
    }
}

impl fmt::Display for ClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}  txid: 0x{:x}", self.msg_type, self.tx_id)
    }
}

impl ClientMsg {
    // Returns an initialized ClientMsg
    pub fn new(msg_type: MsgType, tx_id: Option<u32>) -> ClientMsg {
        let tx_id = match tx_id {
            Some(x) => x,
            None => rand::random(),
        };
        ClientMsg {
            msg_type,
            tx_id: (tx_id & 0xffffff),
            options: Vec::new(),
        }
    }

    // Attempts to parse the contents of the provided buffer, and returns
    // the ClientMsg encoded within.
    pub fn decode(buf: &[u8]) -> Result<ClientMsg> {
        let mut buf = buffer::Buffer::new_from_slice(buf);

        let code = buf.get_8()?;
        let msg_type = MsgType::try_from(code).map_err(|_| Error::UnknownMsgCode(code))?;
        let tx_id = buf.get_24()?;
        let options = options::parse_options(&mut buf)?;
        Ok(ClientMsg {
            msg_type,
            tx_id,
            options,
        })
    }

    // Deparses the provided client message into a DHCPv6 packet
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(2048);

        buf.push(self.msg_type as u8);
        buf.push(((self.tx_id >> 16) & 0xff) as u8);
        buf.push(((self.tx_id >> 8) & 0xff) as u8);
        buf.push((self.tx_id & 0xff) as u8);
        buf.extend_from_slice(&options::encode_options(&self.options)?);
        Ok(buf)
    }

    /// Find the first option of the given type in the message's option list
    pub fn find_one_option(&self, opt_type: u16) -> Option<&options::Dhcpv6Option> {
        find_one_option(&self.options, opt_type)
    }

    /// Find all options of the given type in the message's option list
    pub fn find_all_options(&self, opt_type: u16) -> Vec<&options::Dhcpv6Option> {
        find_all_options(&self.options, opt_type)
    }

    /// Returns 'true' iff the message's option list contains an option of the given type
    pub fn has_option(&self, opt_type: u16) -> bool {
        self.options.iter().any(|o| opt_type == u16::from(o))
    }
}

/// RelayMessage as defined in rfc3315, section 6
pub struct RelayMsg {
    pub msg_type: MsgType,
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub option: Vec<options::Dhcpv6Option>,
}

impl RelayMsg {
    // Attempts to parse the contents of the provided buffer, and returns
    // the RelayMsg encoded within.
    pub fn decode(_buf: &[u8]) -> Result<RelayMsg> {
        Err(Error::Unimplemented("RelayMsg decode".to_string()))
    }

    // Deparses the provided relay message into a DHCPv6 packet
    pub fn encode(_msg: &RelayMsg) -> Result<Vec<u8>> {
        Err(Error::Unimplemented("RelayMsg encode".to_string()))
    }
}
