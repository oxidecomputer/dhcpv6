// Copyright 2021 Oxide Computer Company

pub const SOL_MAX_DELAY: u32 = 1; // Max delay of first Solicit
pub const SOL_TIMEOUT: u32 = 1; // Initial Solicit timeout
pub const SOL_MAX_RT: u32 = 120; // Max Solicit timeout value
pub const REQ_TIMEOUT: u32 = 1; // Initial Request timeout
pub const REQ_MAX_RT: u32 = 30; // Max Request timeout value
pub const REQ_MAX_RC: u32 = 10; //Max Request retry attempts
pub const CNF_MAX_DELAY: u32 = 1; // Max delay of first Confirm
pub const CNF_TIMEOUT: u32 = 1; // Initial Confirm timeout
pub const CNF_MAX_RT: u32 = 4; // Max Confirm timeout
pub const CNF_MAX_RD: u32 = 10; // Max Confirm duration
pub const REN_TIMEOUT: u32 = 10; // Initial Renew timeout
pub const REN_MAX_RT: u32 = 600; // Max Renew timeout value
pub const REB_TIMEOUT: u32 = 10; // Initial Rebind timeout
pub const REB_MAX_RT: u32 = 600; // Max Rebind timeout value
pub const INF_MAX_DELAY: u32 = 1; // Max delay of first Information-request
pub const INF_TIMEOUT: u32 = 1; // Initial Information-request timeout
pub const INF_MAX_RT: u32 = 120; // Max Information-request timeout value
pub const REL_TIMEOUT: u32 = 1; // Initial Release timeout
pub const REL_MAX_RC: u32 = 5; //Max Release attempts
pub const DEC_TIMEOUT: u32 = 1; // Initial Decline timeout
pub const DEC_MAX_RC: u32 = 5; //Max Decline attempts
pub const REC_TIMEOUT: u32 = 2; // Initial Reconfigure timeout
pub const REC_MAX_RC: u32 = 8; //Max Reconfigure attempts
pub const HOP_COUNT_LIMIT: u32 = 32; //Max hop count in a Relay-forward message
