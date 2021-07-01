use std::collections::HashSet;

use crate::buffer::Buffer;
use crate::*;

const IPV6_SIZE: usize = 16; // 16 octets

/// Codes for each of the supported DHCPv6 option types
pub const OPTION_CLIENTID: u16 = 1;
pub const OPTION_SERVERID: u16 = 2;
pub const OPTION_IA_NA: u16 = 3;
pub const OPTION_IA_TA: u16 = 4;
pub const OPTION_IAADDR: u16 = 5;
pub const OPTION_ORO: u16 = 6;
pub const OPTION_PREFERENCE: u16 = 7;
pub const OPTION_ELAPSED_TIME: u16 = 8;
pub const OPTION_RELAY_MSG: u16 = 9;
pub const OPTION_AUTH: u16 = 11;
pub const OPTION_UNICAST: u16 = 12;
pub const OPTION_STATUS_CODE: u16 = 13;
pub const OPTION_RAPID_COMMIT: u16 = 14;
pub const OPTION_USER_CLASS: u16 = 15;
pub const OPTION_VENDOR_CLASS: u16 = 16;
pub const OPTION_VENDOR_OPTS: u16 = 17;
pub const OPTION_INTERFACE_ID: u16 = 18;
pub const OPTION_RECONF_MSG: u16 = 19;
pub const OPTION_RECONF_ACCEPT: u16 = 20;
pub const OPTION_DNS_SERVERS: u16 = 23;
pub const OPTION_DOMAIN_LIST: u16 = 24;

/// All the supported DHCPv6 option types
#[derive(Debug, PartialEq)]
pub enum Dhcpv6Option {
    ClientId(Duid),
    ServerId(Duid),
    IaNa(IaNaOption),
    IaTa(IaTaOption),
    IaAddr(IaAddrOption),
    Oro(Vec<u16>),
    Preference(u8),
    ElapsedTime(u16),
    RelayMsg(Vec<u8>),
    Auth,
    Unicast(Ipv6Addr),
    StatusCode(StatusCodeOption),
    RapidCommit,
    UserClass(Vec<ClassData>),
    VendorClass(VendorClassOption),
    VendorOpts(VendorOption),
    InterfaceId(Vec<u8>),
    ReconfMsg(u8),
    ReconfAccept,
    DnsServers(Vec<Ipv6Addr>),
    DomainList(Vec<String>),
    Other(OtherOption),
}

// Ignore the warning because this is an asymmetric operation
#[allow(clippy::from_over_into)]
impl From<&Dhcpv6Option> for u16 {
    fn from(opt: &Dhcpv6Option) -> u16 {
        match opt {
            Dhcpv6Option::ClientId(_) => OPTION_CLIENTID,
            Dhcpv6Option::ServerId(_) => OPTION_SERVERID,
            Dhcpv6Option::IaNa(_) => OPTION_IA_NA,
            Dhcpv6Option::IaTa(_) => OPTION_IA_TA,
            Dhcpv6Option::IaAddr(_) => OPTION_IAADDR,
            Dhcpv6Option::Oro(_) => OPTION_ORO,
            Dhcpv6Option::Preference(_) => OPTION_PREFERENCE,
            Dhcpv6Option::ElapsedTime(_) => OPTION_ELAPSED_TIME,
            Dhcpv6Option::RelayMsg(_) => OPTION_RELAY_MSG,
            Dhcpv6Option::Auth => OPTION_AUTH,
            Dhcpv6Option::Unicast(_) => OPTION_UNICAST,
            Dhcpv6Option::StatusCode(_) => OPTION_STATUS_CODE,
            Dhcpv6Option::RapidCommit => OPTION_RAPID_COMMIT,
            Dhcpv6Option::UserClass(_) => OPTION_USER_CLASS,
            Dhcpv6Option::VendorClass(_) => OPTION_VENDOR_CLASS,
            Dhcpv6Option::VendorOpts(_) => OPTION_VENDOR_OPTS,
            Dhcpv6Option::InterfaceId(_) => OPTION_INTERFACE_ID,
            Dhcpv6Option::ReconfMsg(_) => OPTION_RECONF_MSG,
            Dhcpv6Option::ReconfAccept => OPTION_RECONF_ACCEPT,
            Dhcpv6Option::DnsServers(_) => OPTION_DNS_SERVERS,
            Dhcpv6Option::DomainList(_) => OPTION_DOMAIN_LIST,
            Dhcpv6Option::Other(x) => x.code,
        }
    }
}

fn hex(data: &[u8]) -> String {
    let mut s = String::new();
    data.iter().for_each(|&v| s.push_str(&format!("{:02x}", v)));
    s
}

// Compare two sets of options.  This comparison requires that every element be
// present in each set.  If an element appears N times in one set, it must
// appear exactly N times in the other.  The order in which elements appear does
// not matter.
pub fn compare_options(a: &[Dhcpv6Option], b: &[Dhcpv6Option]) -> Result<()> {
    if a.len() != b.len() {
        return Err("option counts differ".into());
    }

    let mut to_find = HashSet::new();
    let mut to_match = HashSet::new();
    for i in 0..a.len() {
        to_find.insert(i);
        to_match.insert(i);
    }

    for (idx_a, opt_a) in a.iter().enumerate() {
        for (idx_b, opt_b) in b.iter().enumerate() {
            if to_match.contains(&idx_b) && opt_a == opt_b {
                to_find.remove(&idx_a);
                to_match.remove(&idx_b);
                break;
            }
        }
    }

    if !to_match.is_empty() || !to_find.is_empty() {
        Err(format!(
            "{} extra options.  {} missing options.",
            to_match.len(),
            to_find.len()
        )
        .into())
    } else {
        Ok(())
    }
}

trait OptionParse {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Self>
    where
        Self: Sized;
    fn encode(&self) -> Result<Vec<u8>>;
}

impl OptionParse for Vec<u8> {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Vec<u8>> {
        let d = buf.get_bytes(len)?;
        Ok(d.to_vec())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl OptionParse for Vec<u16> {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Vec<u16>> {
        let cnt = len / 2;
        let mut v = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            v.push(buf.get_16()?);
        }

        Ok(v)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(self.len() * 2);
        self.iter()
            .for_each(|&x| v.extend_from_slice(&x.to_be_bytes()));
        Ok(v)
    }
}

impl OptionParse for Ipv6Addr {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Ipv6Addr> {
        if len < IPV6_SIZE {
            return Err(Error::TooShort);
        }

        buf.get_ipv6addr()
    }

    fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.octets().to_vec())
    }
}

impl OptionParse for Vec<Ipv6Addr> {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Vec<Ipv6Addr>> {
        let cnt = len / IPV6_SIZE;
        if cnt * IPV6_SIZE != len {
            return Err(Error::TooShort);
        }

        let mut v = Vec::new();
        for _ in 0..cnt {
            v.push(buf.get_ipv6addr()?);
        }
        Ok(v)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(IPV6_SIZE * self.len());
        self.iter()
            .for_each(|&ipv6| v.extend_from_slice(&ipv6.octets()));
        Ok(v)
    }
}

#[derive(Eq, Hash, Clone, PartialEq)]
pub struct DuidLLT {
    pub type_code: u16, // constant 1
    pub hw_type: u16,
    pub time: u32,
    pub link_layer: Vec<u8>,
}

impl DuidLLT {
    pub fn new(hw_type: u16, time: u32, ll: &[u8]) -> Result<DuidLLT> {
        if ll.len() <= 120 {
            Ok(DuidLLT {
                type_code: 1,
                hw_type,
                time,
                link_layer: ll.to_vec(),
            })
        } else {
            Err(Error::BadOption("link-layer address too long".into()))
        }
    }
}

impl fmt::Debug for DuidLLT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DUID-LLT code: {}  hw_type: {}  time: {}  addr: {}",
            self.type_code,
            self.hw_type,
            self.time,
            hex(&self.link_layer)
        )
    }
}

impl OptionParse for DuidLLT {
    fn parse(len: usize, buf: &mut Buffer) -> Result<DuidLLT> {
        if len < 7 {
            return Err(Error::TooShort);
        }
        Ok(DuidLLT {
            type_code: 1,
            hw_type: buf.get_16()?,
            time: buf.get_32()?,
            link_layer: buf.get_bytes(len - 6)?,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.type_code.to_be_bytes());
        v.extend_from_slice(&self.hw_type.to_be_bytes());
        v.extend_from_slice(&self.time.to_be_bytes());
        v.extend_from_slice(&self.link_layer.to_vec());
        Ok(v)
    }
}

#[derive(Eq, Hash, Clone, PartialEq)]
pub struct DuidEn {
    pub type_code: u16, // constant 2
    pub enterprise_code: u32,
    pub identifier: Vec<u8>,
}

impl DuidEn {
    pub fn new(enterprise_code: u32, id: &[u8]) -> Result<DuidEn> {
        if id.len() <= 120 {
            Ok(DuidEn {
                type_code: 2,
                enterprise_code,
                identifier: id.to_vec(),
            })
        } else {
            Err(Error::BadOption("identifier too long".into()))
        }
    }
}

impl fmt::Debug for DuidEn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DUID-EN code: {}  enterpise_code: {}  id: {}",
            self.type_code,
            self.enterprise_code,
            hex(&self.identifier)
        )
    }
}

impl OptionParse for DuidEn {
    fn parse(len: usize, buf: &mut Buffer) -> Result<DuidEn> {
        if len < 5 {
            return Err(Error::TooShort);
        }
        Ok(DuidEn {
            type_code: 2,
            enterprise_code: buf.get_32()?,
            identifier: buf.get_bytes(len - 4)?,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.type_code.to_be_bytes());
        v.extend_from_slice(&self.enterprise_code.to_be_bytes());
        v.extend_from_slice(&self.identifier);
        Ok(v)
    }
}

#[derive(Eq, Hash, Clone, PartialEq)]
pub struct DuidLL {
    pub type_code: u16, // constant 3
    pub hw_type: u16,
    pub link_layer: Vec<u8>,
}

impl fmt::Debug for DuidLL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DUID-LL code: {}  hw_type: {} addr: {}",
            self.type_code,
            self.hw_type,
            hex(&self.link_layer)
        )
    }
}

impl DuidLL {
    pub fn new(hw_type: u16, ll: &[u8]) -> Result<DuidLL> {
        if ll.len() <= 124 {
            Ok(DuidLL {
                type_code: 3,
                hw_type,
                link_layer: ll.to_vec(),
            })
        } else {
            Err(Error::BadOption("link-layer address too long".into()))
        }
    }
}

impl OptionParse for DuidLL {
    fn parse(len: usize, buf: &mut Buffer) -> Result<DuidLL> {
        if len < 3 {
            return Err(Error::TooShort);
        }
        Ok(DuidLL {
            type_code: 3,
            hw_type: buf.get_16()?,
            link_layer: buf.get_bytes(len - 6)?,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.type_code.to_be_bytes());
        v.extend_from_slice(&self.hw_type.to_be_bytes());
        v.extend_from_slice(&self.link_layer.to_vec());
        Ok(v)
    }
}

#[derive(Eq, Hash, Clone, Debug, PartialEq)]
pub enum Duid {
    Llt(DuidLLT),
    En(DuidEn),
    Ll(DuidLL),
}

impl OptionParse for Duid {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Duid> {
        let type_code = buf.get_16()?;

        let remaining = len - 2;
        if remaining <= 128 {
            match type_code {
                1 => Ok(Duid::Llt(DuidLLT::parse(remaining, buf)?)),
                2 => Ok(Duid::En(DuidEn::parse(remaining, buf)?)),
                3 => Ok(Duid::Ll(DuidLL::parse(remaining, buf)?)),
                _ => Err(Error::BadOption("invalid DUID type".into())),
            }
        } else {
            Err(Error::BadOption("duid to long".into()))
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Duid::Llt(x) => x.encode(),
            Duid::En(x) => x.encode(),
            Duid::Ll(x) => x.encode(),
        }
    }
}

pub struct IaNaOption {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub options: Vec<Dhcpv6Option>,
}

impl IaNaOption {
    pub fn new(iaid: u32) -> Self {
        IaNaOption {
            iaid,
            t1: 0,
            t2: 0,
            options: Vec::new(),
        }
    }
}

impl PartialEq for IaNaOption {
    fn eq(&self, other: &Self) -> bool {
        self.iaid == other.iaid
            && self.t1 == other.t1
            && self.t2 == other.t2
            && compare_options(&self.options, &other.options).is_ok()
    }
}

impl fmt::Debug for IaNaOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "iaid: {}  t1: {}  t2: {}  options: {:?}",
            self.iaid, self.t1, self.t2, self.options
        )
    }
}

impl OptionParse for IaNaOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<IaNaOption> {
        let iaid = buf.get_32()?;
        let t1 = buf.get_32()?;
        let t2 = buf.get_32()?;
        let options = parse_nested_options(buf, len - 12)?;
        Ok(IaNaOption {
            iaid,
            t1,
            t2,
            options,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.iaid.to_be_bytes());
        v.extend_from_slice(&self.t1.to_be_bytes());
        v.extend_from_slice(&self.t2.to_be_bytes());
        v.extend_from_slice(&encode_options(&self.options)?);
        Ok(v)
    }
}

pub struct IaTaOption {
    pub iaid: u32,
    pub options: Vec<Dhcpv6Option>,
}

impl IaTaOption {
    pub fn new(iaid: u32) -> Self {
        IaTaOption {
            iaid,
            options: Vec::new(),
        }
    }
}

impl PartialEq for IaTaOption {
    fn eq(&self, other: &Self) -> bool {
        self.iaid == other.iaid && compare_options(&self.options, &other.options).is_ok()
    }
}

impl fmt::Debug for IaTaOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "iaid: {}  options: {:?}", self.iaid, self.options)
    }
}

impl OptionParse for IaTaOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<IaTaOption> {
        let iaid = buf.get_32()?;
        let options = parse_nested_options(buf, len - 4)?;
        Ok(IaTaOption { iaid, options })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.iaid.to_be_bytes());
        v.extend_from_slice(&encode_options(&self.options)?);
        Ok(v)
    }
}

pub struct IaAddrOption {
    pub addr: Ipv6Addr,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub options: Vec<Dhcpv6Option>,
}

impl IaAddrOption {
    pub fn new(addr: Ipv6Addr) -> Self {
        IaAddrOption {
            addr,
            preferred_lifetime: 0,
            valid_lifetime: 0,
            options: Vec::new(),
        }
    }
}

impl PartialEq for IaAddrOption {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
            && self.preferred_lifetime == other.preferred_lifetime
            && self.valid_lifetime == other.valid_lifetime
            && compare_options(&self.options, &other.options).is_ok()
    }
}

impl fmt::Debug for IaAddrOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "addr: {}  preferred: {}  valid: {}  options: {:?}",
            self.addr, self.preferred_lifetime, self.valid_lifetime, self.options
        )
    }
}

impl OptionParse for IaAddrOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<IaAddrOption> {
        let addr = buf.get_ipv6addr()?;
        let preferred_lifetime = buf.get_32()?;
        let valid_lifetime = buf.get_32()?;
        let options = parse_nested_options(buf, len - 24)?;
        Ok(IaAddrOption {
            addr,
            preferred_lifetime,
            valid_lifetime,
            options,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.addr.octets());
        v.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        v.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        v.extend_from_slice(&encode_options(&self.options)?);
        Ok(v)
    }
}

#[derive(PartialEq)]
pub struct StatusCodeOption {
    pub code: StatusCode,
    pub msg: Vec<u8>,
}

impl fmt::Debug for StatusCodeOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match std::str::from_utf8(&self.msg) {
            Ok(msg) => msg,
            Err(_) => return Err(std::fmt::Error),
        };
        write!(f, "code: {}  msg: {}", self.code, msg)
    }
}

impl OptionParse for StatusCodeOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<StatusCodeOption> {
        let code = StatusCode::try_from(buf.get_16()?)
            .map_err(|_| Error::Other("invalid status code".to_string()))?;
        let msg = buf.get_bytes(len - 2)?;
        Ok(StatusCodeOption { code, msg })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        let code = self.code as u16;
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&self.msg);
        Ok(v)
    }
}

#[derive(PartialEq)]
pub struct ClassData {
    pub len: usize,
    pub data: Vec<u8>,
}

impl fmt::Debug for ClassData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len: {}  data: {}", self.len, hex(&self.data))
    }
}

impl OptionParse for Vec<ClassData> {
    fn parse(len: usize, buf: &mut Buffer) -> Result<Vec<ClassData>> {
        let data = buf.get_bytes(len)?;
        let mut class_buf = buffer::Buffer::new_from_slice(&data);
        let mut v = Vec::new();
        while class_buf.left() > 0 {
            let len = class_buf.get_16()? as usize;
            let data = class_buf.get_bytes(len)?;
            v.push(ClassData { len, data });
        }

        Ok(v)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        for class in self {
            v.extend_from_slice(&class.len.to_be_bytes());
            v.extend_from_slice(&class.data)
        }
        Ok(v)
    }
}

#[derive(PartialEq)]
pub struct VendorClassOption {
    pub enterprise_number: u32,
    pub data: Vec<ClassData>,
}

impl fmt::Debug for VendorClassOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "enterprise_number: {}  data: {:?}",
            self.enterprise_number, self.data
        )
    }
}

impl OptionParse for VendorClassOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<VendorClassOption> {
        let enterprise_number = buf.get_32()?;
        let data = Vec::<ClassData>::parse(len - 4, buf)?;
        Ok(VendorClassOption {
            enterprise_number,
            data,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.enterprise_number.to_be_bytes());
        for class in &self.data {
            v.extend_from_slice(&class.len.to_be_bytes());
            v.extend_from_slice(&class.data)
        }
        Ok(v)
    }
}

#[derive(PartialEq)]
pub struct VendorOption {
    pub enterprise_number: u32,
    pub data: Vec<u8>,
}

impl fmt::Debug for VendorOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "enterprise_number: {}  data: {}",
            self.enterprise_number,
            hex(&self.data)
        )
    }
}

impl OptionParse for VendorOption {
    fn parse(len: usize, buf: &mut Buffer) -> Result<VendorOption> {
        let enterprise_number = buf.get_32()?;
        let data = buf.get_bytes(len - 4)?;
        Ok(VendorOption {
            enterprise_number,
            data,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.enterprise_number.to_be_bytes());
        v.extend_from_slice(&self.data);
        Ok(v)
    }
}

fn domain_validate(domain: &str) -> Result<()> {
    if domain.len() > 253 {
        return Err(Error::BadOption("domain name too large".to_string()));
    }

    let mut first = true;
    let mut label_size = 0;
    for c in domain.chars() {
        if !c.is_ascii() {
            return Err(Error::BadOption("non-ascii domain name".to_string()));
        }

        if first && !c.is_ascii_alphabetic() {
            return Err(Error::BadOption(
                "domain doesn't start with a letter".to_string(),
            ));
        }
        first = false;
        if c == '.' {
            label_size = 0;
            continue;
        }

        label_size += 1;
        if label_size > 63 {
            return Err(Error::BadOption("domain lable too large".to_string()));
        }

        if !(c.is_alphanumeric() && c != '-') {
            return Err(Error::BadOption("invalid domain name".to_string()));
        }
    }
    Ok(())
}

fn domain_list_encode(opt: &[String]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    for domain in opt {
        domain_validate(domain)?;

        let mut labels = 0;
        for label in domain.split('.') {
            if !label.is_empty() {
                labels += 1;
                v.push(label.len() as u8);
                v.extend_from_slice(&label.as_bytes());
            }
        }
        if labels > 0 {
            v.push(0);
        }
    }
    Ok(v)
}

fn domain_parse(mut buf: Vec<u8>) -> Result<(String, Vec<u8>)> {
    let mut domain = String::new();

    while !buf.is_empty() {
        let len = buf.remove(0) as usize;
        if len == 0 {
            break;
        }
        if len > buf.len() {
            return Err(Error::BadOption("domain option overflow".to_string()));
        }

        if !domain.is_empty() {
            domain.push('.');
        }
        for _ in 0..len {
            let c = match std::char::from_u32(buf.remove(0) as u32) {
                Some(c) => c,
                None => {
                    return Err(Error::BadOption(
                        "domain contains invalid character".to_string(),
                    ))
                }
            };
            domain.push(c);
        }
    }
    domain_validate(&domain)?;
    Ok((domain, buf))
}

fn domain_list_parse(len: usize, buf: &mut Buffer) -> Result<Vec<String>> {
    let mut data = buf.get_bytes(len)?;
    let mut list = Vec::new();

    while !data.is_empty() {
        let (domain, remainder) = domain_parse(data)?;
        if domain.len() > 255 {
            return Err(Error::BadOption("domain too large".to_string()));
        }
        list.push(domain);
        data = remainder;
    }
    Ok(list)
}

#[derive(PartialEq)]
pub struct OtherOption {
    pub code: u16,
    pub len: usize,
    pub data: Vec<u8>,
}

impl fmt::Debug for OtherOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "code: {} len: {} data: {}",
            self.code,
            self.len,
            hex(&self.data)
        )
    }
}

fn other_option(code: u16, len: usize, buf: &mut Buffer) -> Result<OtherOption> {
    Ok(OtherOption {
        code,
        len,
        data: buf.get_bytes(len)?,
    })
}

fn encode_one(opt: &Dhcpv6Option) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    let data = match opt {
        Dhcpv6Option::ClientId(x) => x.encode()?,
        Dhcpv6Option::ServerId(x) => x.encode()?,
        Dhcpv6Option::IaNa(x) => x.encode()?,
        Dhcpv6Option::IaTa(x) => x.encode()?,
        Dhcpv6Option::IaAddr(x) => x.encode()?,
        Dhcpv6Option::Oro(x) => x.encode()?,
        Dhcpv6Option::Preference(x) => (*x).to_be_bytes().to_vec(),
        Dhcpv6Option::ElapsedTime(x) => (*x).to_be_bytes().to_vec(),
        Dhcpv6Option::RelayMsg(x) => x.encode()?,
        Dhcpv6Option::Auth => {
            return Err(Error::Unimplemented("Authentication option".to_string()))
        }
        Dhcpv6Option::Unicast(x) => x.encode()?,
        Dhcpv6Option::StatusCode(x) => x.encode()?,
        Dhcpv6Option::RapidCommit => Vec::new(), // no payload to push
        Dhcpv6Option::UserClass(x) => x.encode()?,
        Dhcpv6Option::VendorClass(x) => x.encode()?,
        Dhcpv6Option::VendorOpts(x) => x.encode()?,
        Dhcpv6Option::InterfaceId(x) => x.encode()?,
        Dhcpv6Option::ReconfMsg(x) => vec![*x],
        Dhcpv6Option::ReconfAccept => Vec::new(), // no payload to push
        Dhcpv6Option::DnsServers(x) => x.encode()?,
        Dhcpv6Option::DomainList(x) => domain_list_encode(&x)?,
        Dhcpv6Option::Other(x) => x.data.to_vec(),
    };
    let code: u16 = opt.into();
    v.extend_from_slice(&code.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(&data);

    Ok(v)
}

pub fn encode_options(opts: &[Dhcpv6Option]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    for opt in opts {
        v.extend_from_slice(&encode_one(opt)?);
    }
    Ok(v)
}

fn parse_one(buf: &mut Buffer) -> Result<Dhcpv6Option> {
    let code = buf.get_16()?;
    let len = buf.get_16()? as usize;
    let next = buf.get_offset() + len;

    let opt = match code {
        OPTION_CLIENTID => Dhcpv6Option::ClientId(Duid::parse(len, buf)?),
        OPTION_SERVERID => Dhcpv6Option::ServerId(Duid::parse(len, buf)?),
        OPTION_IA_NA => Dhcpv6Option::IaNa(IaNaOption::parse(len, buf)?),
        OPTION_IA_TA => Dhcpv6Option::IaTa(IaTaOption::parse(len, buf)?),
        OPTION_IAADDR => Dhcpv6Option::IaAddr(IaAddrOption::parse(len, buf)?),
        OPTION_ORO => Dhcpv6Option::Oro(Vec::<u16>::parse(len, buf)?),
        OPTION_PREFERENCE => Dhcpv6Option::Preference(buf.get_8()?),
        OPTION_ELAPSED_TIME => Dhcpv6Option::ElapsedTime(buf.get_16()?),
        OPTION_RELAY_MSG => Dhcpv6Option::RelayMsg(Vec::<u8>::parse(len, buf)?),
        OPTION_AUTH => return Err(Error::Unimplemented("Authentication option".to_string())),
        OPTION_UNICAST => Dhcpv6Option::Unicast(buf.get_ipv6addr()?),
        OPTION_STATUS_CODE => Dhcpv6Option::StatusCode(StatusCodeOption::parse(len, buf)?),
        OPTION_RAPID_COMMIT => Dhcpv6Option::RapidCommit,
        OPTION_USER_CLASS => Dhcpv6Option::UserClass(Vec::<ClassData>::parse(len, buf)?),
        OPTION_VENDOR_CLASS => Dhcpv6Option::VendorClass(VendorClassOption::parse(len, buf)?),
        OPTION_VENDOR_OPTS => Dhcpv6Option::VendorOpts(VendorOption::parse(len, buf)?),
        OPTION_INTERFACE_ID => Dhcpv6Option::InterfaceId(Vec::<u8>::parse(len, buf)?),
        OPTION_RECONF_MSG => Dhcpv6Option::ReconfMsg(buf.get_8()?),
        OPTION_RECONF_ACCEPT => Dhcpv6Option::ReconfAccept,
        OPTION_DNS_SERVERS => Dhcpv6Option::DnsServers(Vec::<Ipv6Addr>::parse(len, buf)?),
        OPTION_DOMAIN_LIST => Dhcpv6Option::DomainList(domain_list_parse(len, buf)?),
        _ => Dhcpv6Option::Other(other_option(code, len, buf)?),
    };
    buf.set_offset(next)?;
    Ok(opt)
}

fn parse_nested_options(buf: &mut Buffer, len: usize) -> Result<Vec<Dhcpv6Option>> {
    let data = buf.get_bytes(len)?;
    let mut options_buf = buffer::Buffer::new_from_slice(&data);
    parse_options(&mut options_buf)
}

pub fn parse_options(buf: &mut Buffer) -> Result<Vec<Dhcpv6Option>> {
    let mut opts = Vec::new();

    while buf.left() > 0 {
        opts.push(parse_one(buf)?);
    }

    Ok(opts)
}
