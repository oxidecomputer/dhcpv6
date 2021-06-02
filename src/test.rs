use crate::*;

#[cfg(test)]
fn decode_hex(ascii: &str) -> std::result::Result<Vec<u8>, String> {
    let mut low = true;
    let mut rval = Vec::new();
    let mut dig = 0;
    for l in ascii.chars() {
        if l.is_ascii_whitespace() {
            continue;
        } else if let Some(v) = l.to_digit(16) {
            if low {
                dig = v as u8;
                low = false;
            } else {
                rval.push((dig << 4) | v as u8);
                low = true;
            }
        } else {
            return Err("invalid hex string".to_string());
        }
    }
    if !low {
        rval.push(dig);
    }

    Ok(rval)
}

#[test]
fn test_decode_hex() {
    assert_eq!(decode_hex("9").unwrap(), vec![0x9]);
    assert_eq!(decode_hex("19").unwrap(), vec![0x19]);
    assert_eq!(decode_hex("a").unwrap(), vec![0xa]);
    assert_eq!(decode_hex("ab").unwrap(), vec![0xab]);
    assert_eq!(decode_hex("19ab").unwrap(), vec![0x19, 0xab]);
    assert_eq!(decode_hex("19 ab").unwrap(), vec![0x19, 0xab]);
    assert_eq!(
        decode_hex("19 ab cd 0123").unwrap(),
        vec![0x19, 0xab, 0xcd, 0x01, 0x23]
    );

    assert_eq!(
        decode_hex("19 ab cd 01 2").unwrap(),
        vec![0x19, 0xab, 0xcd, 0x01, 0x2]
    );
    let expected = Err("invalid hex string".to_string());
    assert_eq!(decode_hex("19 ax cd 01 2"), expected);
}

#[test]
fn test_request() {
    let z = decode_hex(
        "0322 407a 0001 000e 0001 0001 2841 2860
         0208 20b3 b93e 0002 000e 0001 0001 2841
         2881 0208 20b3 b93e 0003 000c 0000 0003
         0000 0000 0000 0000 0006 000c 0007 000c
         0017 0018 001b 001d 0008 0002 0000",
    )
    .unwrap();

    let client_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x28412860,
        link_layer: vec![0x02, 0x08, 0x20, 0xb3, 0xb9, 0x3e],
    });

    let server_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x28412881,
        link_layer: vec![0x02, 0x08, 0x20, 0xb3, 0xb9, 0x3e],
    });

    let ia_na = options::IaNaOption {
        iaid: 3,
        t1: 0,
        t2: 0,
        options: Vec::new(),
    };
    let opt_req = vec![7, 12, 23, 24, 27, 29];

    let expected = ClientMsg {
        msg_type: MsgType::Request,
        tx_id: 0x22407a,
        options: vec![
            options::Dhcpv6Option::ClientId(client_id),
            options::Dhcpv6Option::ServerId(server_id),
            options::Dhcpv6Option::IaNa(ia_na),
            options::Dhcpv6Option::Oro(opt_req),
            options::Dhcpv6Option::ElapsedTime(0),
        ],
    };

    let decoded = ClientMsg::decode(&z).unwrap();
    assert_eq!(decoded, expected);

    let encoded = ClientMsg::encode(&decoded).unwrap();
    assert_eq!(encoded, z);
}

#[test]
fn test_solicit() {
    let z = decode_hex(
        "01a3 1b8f 0001 000e 0001 0001 27f8 d12f
	 0208 2018 e7ea 0003 000c 0000 0002 0000
	 0000 0000 0000 0006 000c 0007 000c 0017
	 0018 001b 001d 000e 0000 0008 0002 0000",
    )
    .unwrap();

    let client_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x27f8d12f,
        link_layer: vec![0x02, 0x08, 0x20, 0x18, 0xe7, 0xea],
    });

    let ia_na = options::IaNaOption {
        iaid: 2,
        t1: 0,
        t2: 0,
        options: Vec::new(),
    };
    let opt_req = vec![7, 12, 23, 24, 27, 29];

    let expected = ClientMsg {
        msg_type: MsgType::Solicit,
        tx_id: 0xa31b8f,
        options: vec![
            options::Dhcpv6Option::ClientId(client_id),
            options::Dhcpv6Option::IaNa(ia_na),
            options::Dhcpv6Option::Oro(opt_req),
            options::Dhcpv6Option::RapidCommit,
            options::Dhcpv6Option::ElapsedTime(0),
        ],
    };

    let decoded = ClientMsg::decode(&z).unwrap();
    assert_eq!(decoded, expected);

    let encoded = ClientMsg::encode(&decoded).unwrap();
    assert_eq!(encoded, z);
}

#[test]
fn test_renew() {
    let z = decode_hex(
        "05db fac2 0001 000e 0001 0001 2841 2860
	 0208 20b3 b93e 0002 000e 0001 0001 2841
	 2881 0208 20b3 b93e 0003 0044 0000 0003
	 0000 0000 0000 0000 0005 0018 fd00 aabb
	 ccdd 0024 0000 0000 0000 7000 0000 004b
	 0000 0078 0005 0018 fd00 aabb ccdd 0024
	 0000 0000 0000 658e 0000 004b 0000 0078
	 0006 000c 0007 000c 0017 0018 001b 001d
	 0008 0002 0000",
    )
    .unwrap();

    let client_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x28412860,
        link_layer: vec![0x02, 0x08, 0x20, 0xb3, 0xb9, 0x3e],
    });

    let server_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x28412881,
        link_layer: vec![0x02, 0x08, 0x20, 0xb3, 0xb9, 0x3e],
    });

    let addr1 = options::IaAddrOption {
        addr: "fd00:aabb:ccdd:24::7000".parse().unwrap(),
        preferred_lifetime: 75,
        valid_lifetime: 120,
        options: Vec::new(),
    };
    let addr2 = options::IaAddrOption {
        addr: "fd00:aabb:ccdd:24::658e".parse().unwrap(),
        preferred_lifetime: 75,
        valid_lifetime: 120,
        options: Vec::new(),
    };
    let ia_na = options::IaNaOption {
        iaid: 3,
        t1: 0,
        t2: 0,
        options: vec![
            options::Dhcpv6Option::IaAddr(addr1),
            options::Dhcpv6Option::IaAddr(addr2),
        ],
    };
    let opt_req = vec![7, 12, 23, 24, 27, 29];

    let expected = ClientMsg {
        msg_type: MsgType::Renew,
        tx_id: 0xdbfac2,
        options: vec![
            options::Dhcpv6Option::ClientId(client_id),
            options::Dhcpv6Option::ServerId(server_id),
            options::Dhcpv6Option::IaNa(ia_na),
            options::Dhcpv6Option::Oro(opt_req),
            options::Dhcpv6Option::ElapsedTime(0),
        ],
    };

    let decoded = ClientMsg::decode(&z).unwrap();
    assert_eq!(decoded, expected);

    let encoded = ClientMsg::encode(&decoded).unwrap();
    assert_eq!(encoded, z);
}

#[test]
fn test_advertise() {
    let z = decode_hex(
        "0243 35e9 0003 0028 0000 0002 0000 0000
	 0000 0000 0005 0018 fd00 aabb ccdd 0024
	 0000 0000 0000 6b10 0000 08ca 0000 0e10
	 0001 000e 0001 0001 27f8 d12f 0208 2018
	 e7ea 0002 000e 0001 0001 2841 2881 0208
	 20b3 b93e 0017 0020 fd00 aabb ccdd 0024
	 0000 0000 0000 0080 2001 4860 4860 0000
	 0000 0000 0000 8888 0018 0015 0365 6e67
	 0005 6f78 6964 6508 636f 6d70 7574 6572
	 00",
    )
    .unwrap();

    let client_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x27f8d12f,
        link_layer: vec![0x02, 0x08, 0x20, 0x18, 0xe7, 0xea],
    });

    let server_id = options::Duid::Llt(options::DuidLLT {
        type_code: 1,
        hw_type: 1,
        time: 0x28412881,
        link_layer: vec![0x02, 0x08, 0x20, 0xb3, 0xb9, 0x3e],
    });

    let addr = options::IaAddrOption {
        addr: "fd00:aabb:ccdd:24::6b10".parse().unwrap(),
        preferred_lifetime: 2250,
        valid_lifetime: 3600,
        options: Vec::new(),
    };
    let ia_na = options::IaNaOption {
        iaid: 2,
        t1: 0,
        t2: 0,
        options: vec![options::Dhcpv6Option::IaAddr(addr)],
    };
    let dns1: Ipv6Addr = "fd00:aabb:ccdd:24::80".parse().unwrap();
    let dns2: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    let nameservers = vec![dns1, dns2];
    let domains = vec!["eng".to_string(), "oxide.computer".to_string()];

    let expected = ClientMsg {
        msg_type: MsgType::Advertise,
        tx_id: 0x4335e9,
        options: vec![
            options::Dhcpv6Option::IaNa(ia_na),
            options::Dhcpv6Option::ClientId(client_id),
            options::Dhcpv6Option::ServerId(server_id),
            options::Dhcpv6Option::DnsServers(nameservers),
            options::Dhcpv6Option::DomainList(domains),
        ],
    };

    let decoded = ClientMsg::decode(&z).unwrap();
    assert_eq!(decoded, expected);

    let encoded = ClientMsg::encode(&decoded).unwrap();
    assert_eq!(encoded, z);
}
