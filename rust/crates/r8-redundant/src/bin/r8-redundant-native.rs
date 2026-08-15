use core::num::NonZeroU64;
use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use r8_mobility::{
    CandidateManager, CandidateManagerConfig, Control, Policy, Profile3AdmissionOwner,
};
use r8_proto::Header;
use r8_redundant::{ReceiveOutcome, RedundantSession, SendOutcome};
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, ObservedBinding, ServerMachine,
    ServerMaterial,
};
use r8d::drop_privileges;
use zeroize::Zeroize;

const ETHERTYPE: u16 = 0x88b5;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const SOL_PACKET: libc::c_int = 263;
const CONTROL_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];
const CLIENT_LOC: [u8; 16] = [
    0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
];
const SERVER_LOC: [u8; 16] = [
    255, 238, 221, 204, 187, 170, 153, 136, 119, 102, 85, 68, 51, 34, 17, 0,
];
const KEY_FD: i32 = 3;
const KEY_MATERIAL_LEN: usize = 64;
const ENDPOINT_UID: libc::uid_t = 65534;
const ENDPOINT_GID: libc::gid_t = 65534;

struct Args {
    mode: Mode,
    interfaces: [String; 2],
    local: [[u8; 6]; 2],
    peer: [[u8; 6]; 2],
}

enum Mode {
    Send,
    Receive,
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0; 6];
    for (index, part) in parts.into_iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        mac[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn args() -> Option<Args> {
    let values: Vec<String> = std::env::args().collect();
    if values.len() != 8 {
        return None;
    }
    let mode = match values[1].as_str() {
        "send" => Mode::Send,
        "receive" => Mode::Receive,
        _ => return None,
    };
    Some(Args {
        mode,
        interfaces: [values[2].clone(), values[3].clone()],
        local: [parse_mac(&values[4])?, parse_mac(&values[6])?],
        peer: [parse_mac(&values[5])?, parse_mac(&values[7])?],
    })
}

fn binding(descriptor_id: u32, source: [u8; 6]) -> ObservedBinding {
    ObservedBinding::Native {
        ingress_descriptor_id: descriptor_id,
        next_hop_mac: source,
    }
}

struct Credentials {
    signing: SigningKey,
    local: Identity,
    peer: Identity,
}

fn random<const N: usize>() -> Result<[u8; N], ()> {
    let mut value = [0; N];
    let mut filled = 0;
    while filled != N {
        let count =
            unsafe { libc::getrandom(value[filled..].as_mut_ptr() as *mut _, N - filled, 0) };
        if count <= 0 {
            value.zeroize();
            return Err(());
        }
        filled += count as usize;
    }
    Ok(value)
}

fn credentials(role: u8) -> Result<Credentials, ()> {
    if unsafe { libc::fcntl(KEY_FD, libc::F_GETFD) } == -1 {
        return Err(());
    }
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(KEY_FD, &mut stat) } != 0
        || (stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK
    {
        return Err(());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(KEY_FD) };
    let mut material = [0u8; KEY_MATERIAL_LEN];
    let mut filled = 0;
    while filled != material.len() {
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                material[filled..].as_mut_ptr() as *mut _,
                material.len() - filled,
            )
        };
        if count <= 0 {
            material.zeroize();
            return Err(());
        }
        filled += count as usize;
    }
    let mut extra = [0u8; 1];
    if unsafe { libc::read(fd.as_raw_fd(), extra.as_mut_ptr() as *mut _, 1) } != 0 {
        material.zeroize();
        return Err(());
    }
    let signing = SigningKey::from_bytes(material[..32].try_into().map_err(|_| ())?);
    let peer_public: [u8; 32] = material[32..].try_into().map_err(|_| ())?;
    material.zeroize();
    let local =
        Identity::from_public_key(role, 7, signing.verifying_key().to_bytes()).map_err(|_| ())?;
    let peer =
        Identity::from_public_key(if role == 1 { 2 } else { 1 }, 7, peer_public).map_err(|_| ())?;
    Ok(Credentials {
        signing,
        local,
        peer,
    })
}

fn random_scid() -> Result<u64, ()> {
    loop {
        let value = u64::from_be_bytes(random()?);
        if value != 0 {
            return Ok(value);
        }
    }
}

fn manager(
    credentials: &Credentials,
    local_loc: [u8; 16],
    peer_loc: [u8; 16],
    scid: u64,
    carrier: ObservedBinding,
    owner: Profile3AdmissionOwner,
) -> Result<CandidateManager, ()> {
    CandidateManager::new_with_profile3_admission_owner(
        CandidateManagerConfig {
            signing: credentials.signing.clone(),
            local: credentials.local.clone(),
            peer: credentials.peer.clone(),
            profile: 3,
            scid,
            policy: Policy { policy_id: 9 },
            local_loc,
            peer_loc,
            initial_peer_binding: carrier,
            candidate_secret: random()?,
        },
        owner,
    )
    .map_err(|_| ())
}

fn commit_control(
    receiver: &mut RedundantSession,
    manager: &CandidateManager,
    observed_binding: &ObservedBinding,
    packet: &[u8],
    now_ms: u64,
) -> Result<Option<Control>, ()> {
    let receive_preview = receiver
        .preview_mobility_inbound(0, observed_binding, packet, now_ms)
        .map_err(|_| ())?;
    let commit = receiver
        .prepare_mobility_commit(manager, observed_binding, receive_preview, now_ms)
        .map_err(|_| ())?;
    let response = receiver
        .mobility_response(manager, &commit)
        .map_err(|_| ())?;
    receiver.commit_mobility(manager, commit).map_err(|_| ())?;
    Ok(response)
}

fn client_session(
    credentials: &Credentials,
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
) -> Result<(RedundantSession, u64), ()> {
    let scid = random_scid()?;
    let config = HandshakeConfig {
        local: credentials.local.clone(),
        peer: credentials.peer.clone(),
        profile: 3,
        source: CLIENT_LOC,
        destination: SERVER_LOC,
        budget: 1280,
        pending_limit: 4,
        established_limit: 4,
        server_context_id: 1,
    };
    let mut client = ClientMachine::new(config, credentials.signing.clone()).map_err(|_| ())?;
    let open = client
        .start(
            scid,
            ClientMaterial {
                ephemeral_secret: random()?,
                nonce: random()?,
            },
            0,
        )
        .map_err(|_| ())?;
    let started = Instant::now();
    let deadline = started.checked_add(Duration::from_secs(5)).ok_or(())?;
    let mut next_retry = 0;
    let carrier = ClientCarrier {
        fd,
        index,
        local,
        peer,
        descriptor_id: 2,
    };
    transmit(fd, index, local, peer, &open).map_err(|_| ())?;
    let (verify, _) =
        receive_client_control(&mut client, &carrier, started, deadline, &mut next_retry)?;
    let auth = client
        .receive_verify(&verify, elapsed_ms(started)?)
        .map_err(|_| ())?;
    transmit(fd, index, local, peer, &auth).map_err(|_| ())?;
    let (ack, _) =
        receive_client_control(&mut client, &carrier, started, deadline, &mut next_retry)?;
    let accept = client
        .receive_ack(&ack, elapsed_ms(started)?)
        .map_err(|_| ())?;
    transmit(fd, index, local, peer, &accept).map_err(|_| ())?;
    let bootstrap = client.take_profile3_bootstrap().map_err(|_| ())?;
    let delivery = NonZeroU64::new(random_scid()?).ok_or(())?;
    Ok((
        RedundantSession::new(bootstrap, binding(2, peer), delivery).map_err(|_| ())?,
        scid,
    ))
}

fn server_session(
    credentials: &Credentials,
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
) -> Result<(RedundantSession, u64), ()> {
    let started = Instant::now();
    let listen_deadline = deadline_after(Duration::from_secs(5))?;
    let config = HandshakeConfig {
        local: credentials.local.clone(),
        peer: credentials.peer.clone(),
        profile: 3,
        source: CLIENT_LOC,
        destination: SERVER_LOC,
        budget: 1280,
        pending_limit: 4,
        established_limit: 4,
        server_context_id: 1,
    };
    let mut server = ServerMachine::new(
        config,
        credentials.signing.clone(),
        ServerMaterial {
            boot_instance: random()?,
            current_cookie_key: random()?,
            previous_cookie_key: random()?,
            previous_key_rotated_ms: 0,
        },
    )
    .map_err(|_| ())?;
    let (open, observed) = receive_control(fd, index, local, peer, 4, listen_deadline)?;
    let scid = Header::unpack(&open).map_err(|_| ())?.0.scid;
    let verify = server.receive_open(&open, &observed, 0).map_err(|_| ())?;
    transmit(fd, index, local, peer, &verify).map_err(|_| ())?;
    let auth_deadline = deadline_after(Duration::from_secs(5))?;
    let (auth, observed) = receive_control(fd, index, local, peer, 4, auth_deadline)?;
    let ack = server
        .receive_open_auth(
            &auth,
            &observed,
            elapsed_ms(started)?,
            0,
            Some(ServerMaterial::handshake_material(random()?, random()?)),
        )
        .map_err(|_| ())?;
    let pending_deadline = deadline_after(Duration::from_secs(5))?;
    transmit(fd, index, local, peer, &ack).map_err(|_| ())?;
    let (accept, _) = receive_control(fd, index, local, peer, 4, pending_deadline)?;
    server
        .receive_accept(&accept, elapsed_ms(started)?)
        .map_err(|_| ())?;
    let bootstrap = server.take_profile3_bootstrap(scid).map_err(|_| ())?;
    let delivery = NonZeroU64::new(random_scid()?).ok_or(())?;
    Ok((
        RedundantSession::new(bootstrap, binding(4, peer), delivery).map_err(|_| ())?,
        scid,
    ))
}

fn socket(interface: &str) -> io::Result<(OwnedFd, i32)> {
    let name = CString::new(interface).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
    if index <= 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(ETHERTYPE.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let ignore: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            &ignore as *const _ as *const _,
            size_of::<libc::c_int>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as _;
    address.sll_protocol = ETHERTYPE.to_be();
    address.sll_ifindex = index;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const _,
            size_of::<libc::sockaddr_ll>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, index))
}

fn transmit(
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
    payload: &[u8],
) -> io::Result<()> {
    let length = 14usize
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
    if payload.len() > 1280 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&peer);
    frame.extend_from_slice(&local);
    frame.extend_from_slice(&ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(payload);
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as _;
    address.sll_protocol = ETHERTYPE.to_be();
    address.sll_ifindex = index;
    address.sll_halen = 6;
    address.sll_addr[..6].copy_from_slice(&peer);
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr() as *const _,
            frame.len(),
            0,
            &address as *const _ as *const _,
            size_of::<libc::sockaddr_ll>() as _,
        )
    };
    if sent < 0 || usize::try_from(sent).ok() != Some(frame.len()) {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const MAX_FRAME_LEN: usize = 14 + 1280;

fn accepted_frame(buffer: &[u8], count: usize, local: [u8; 6], peer: [u8; 6]) -> Option<&[u8]> {
    if !(14..=MAX_FRAME_LEN).contains(&count)
        || count > buffer.len()
        || buffer[..6] != local
        || buffer[6..12] != peer
        || buffer[12..14] != ETHERTYPE.to_be_bytes()
    {
        return None;
    }
    Some(&buffer[14..count])
}

fn receive(
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
    deadline: Instant,
) -> io::Result<(Vec<u8>, [u8; 6])> {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ETIMEDOUT))?;
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut pollfd,
                1,
                left.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready == 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        // The extra byte is a truncation sentinel: a full payload is accepted, but
        // a frame with any appended byte cannot be authenticated as its prefix.
        let mut buffer = [0u8; MAX_FRAME_LEN + 1];
        let mut address: libc::sockaddr_ll = unsafe { zeroed() };
        let mut address_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let count = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                0,
                &mut address as *mut _ as *mut _,
                &mut address_len,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if address_len as usize != size_of::<libc::sockaddr_ll>()
            || address.sll_ifindex != index
            || address.sll_halen != 6
        {
            continue;
        }
        let source: [u8; 6] = address.sll_addr[..6]
            .try_into()
            .expect("sockaddr_ll length");
        if source != peer {
            continue;
        }
        if let Some(payload) = accepted_frame(&buffer, count as usize, local, peer) {
            return Ok((payload.to_vec(), source));
        }
    }
}

fn receive_control(
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
    descriptor_id: u32,
    deadline: Instant,
) -> Result<(Vec<u8>, ObservedBinding), ()> {
    let (packet, source) = receive(fd, index, local, peer, deadline).map_err(|_| ())?;
    Ok((packet, binding(descriptor_id, source)))
}
fn control_retry_offset(index: usize) -> Result<Duration, ()> {
    CONTROL_RETRY_DELAYS[..=index]
        .iter()
        .try_fold(Duration::ZERO, |total, delay| total.checked_add(*delay))
        .ok_or(())
}
struct ClientCarrier<'a> {
    fd: &'a OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
    descriptor_id: u32,
}

fn receive_client_control(
    client: &mut ClientMachine,
    carrier: &ClientCarrier<'_>,
    started: Instant,
    deadline: Instant,
    next_retry: &mut usize,
) -> Result<(Vec<u8>, ObservedBinding), ()> {
    while *next_retry < CONTROL_RETRY_DELAYS.len()
        && started
            .checked_add(control_retry_offset(*next_retry)?)
            .ok_or(())?
            <= Instant::now()
    {
        *next_retry += 1;
    }
    loop {
        let retry_deadline = if *next_retry < CONTROL_RETRY_DELAYS.len() {
            started
                .checked_add(control_retry_offset(*next_retry)?)
                .ok_or(())?
                .min(deadline)
        } else {
            deadline
        };
        match receive(
            carrier.fd,
            carrier.index,
            carrier.local,
            carrier.peer,
            retry_deadline,
        ) {
            Ok((packet, source)) => {
                return Ok((packet, binding(carrier.descriptor_id, source)));
            }
            Err(error)
                if error.raw_os_error() == Some(libc::ETIMEDOUT)
                    && *next_retry < CONTROL_RETRY_DELAYS.len()
                    && retry_deadline < deadline =>
            {
                let retry = client.retry(elapsed_ms(started)?).map_err(|_| ())?;
                transmit(
                    carrier.fd,
                    carrier.index,
                    carrier.local,
                    carrier.peer,
                    &retry,
                )
                .map_err(|_| ())?;
                *next_retry += 1;
            }
            Err(_) => return Err(()),
        }
    }
}

fn elapsed_ms(start: Instant) -> Result<u64, ()> {
    u64::try_from(start.elapsed().as_millis()).map_err(|_| ())
}
fn deadline_after(duration: Duration) -> Result<Instant, ()> {
    Instant::now().checked_add(duration).ok_or(())
}

fn deadline_at_ms(start: Instant, absolute_ms: u64) -> Result<Instant, ()> {
    start
        .checked_add(Duration::from_millis(absolute_ms))
        .ok_or(())
}

fn send_control(
    state: &mut RedundantSession,
    fd: &OwnedFd,
    index: i32,
    local: [u8; 6],
    peer: [u8; 6],
    control: &Control,
) -> Result<(), ()> {
    let packets = match state
        .outbound(&control.encode().map_err(|_| ())?)
        .map_err(|_| ())?
    {
        SendOutcome::Enqueued { packets, .. } => packets,
        SendOutcome::DroppedNewest => return Err(()),
    };
    if packets.len() != 1 || packets[0].slot() != 0 {
        return Err(());
    }
    let packet = packets[0].packet();
    transmit(fd, index, local, peer, packet).map_err(|_| ())?;
    state.confirm_sent(0, packet).map_err(|_| ())
}

fn run(args: Args) -> Result<(), ()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(());
    }
    let credentials = credentials(if matches!(&args.mode, Mode::Send) {
        1
    } else {
        2
    })?;
    let started = Instant::now();
    let (fd0, index0) = socket(&args.interfaces[0]).map_err(|_| ())?;
    let (fd1, index1) = socket(&args.interfaces[1]).map_err(|_| ())?;
    drop_privileges(ENDPOINT_UID, ENDPOINT_GID).map_err(|_| ())?;
    match args.mode {
        Mode::Send => {
            let (mut state, scid) =
                client_session(&credentials, &fd0, index0, args.local[0], args.peer[0])?;
            let owner = state.issue_profile3_admission_owner(9).map_err(|_| ())?;
            let mover = manager(
                &credentials,
                CLIENT_LOC,
                SERVER_LOC,
                scid,
                binding(2, args.peer[0]),
                owner,
            )?;
            let candidate_loc = random()?;
            let candidate_id = random()?;
            let proposal_now_ms = elapsed_ms(started)?;
            let candidate_deadline =
                deadline_at_ms(started, proposal_now_ms.checked_add(5_000).ok_or(())?)?;
            let update = mover
                .propose_local(candidate_id, candidate_loc, 1, 1, proposal_now_ms)
                .map_err(|_| ())?;
            send_control(
                &mut state,
                &fd0,
                index0,
                args.local[0],
                args.peer[0],
                &update,
            )?;
            let probe = mover
                .make_probe(
                    candidate_id,
                    binding(3, args.peer[1]),
                    random()?,
                    elapsed_ms(started)?,
                )
                .map_err(|_| ())?;
            send_control(
                &mut state,
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                &probe,
            )?;
            let (challenge, challenge_binding) = receive_control(
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                3,
                candidate_deadline,
            )?;
            let response = commit_control(
                &mut state,
                &mover,
                &challenge_binding,
                &challenge,
                elapsed_ms(started)?,
            )?
            .ok_or(())?;
            send_control(
                &mut state,
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                &response,
            )?;
            let (result, result_binding) = receive_control(
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                3,
                candidate_deadline,
            )?;
            if commit_control(
                &mut state,
                &mover,
                &result_binding,
                &result,
                elapsed_ms(started)?,
            )?
            .is_some()
            {
                return Err(());
            }
            let mut admissions = mover.take_profile3_admissions();
            if admissions.len() != 1 {
                return Err(());
            }
            state
                .activate(admissions.pop().ok_or(())?, 1280)
                .map_err(|_| ())?;
            println!("R8-ENDPOINT-READY handshake=5 candidate=5 application=2 total=12");
            let plaintext = [0x5a; 64];
            let packets = match state.outbound(&plaintext).map_err(|_| ())? {
                SendOutcome::Enqueued { packets, .. } => packets,
                SendOutcome::DroppedNewest => return Err(()),
            };
            if packets.len() != 2 {
                return Err(());
            }
            for packet in packets {
                let (fd, index, local, peer) = match packet.slot() {
                    0 => (&fd0, index0, args.local[0], args.peer[0]),
                    1 => (&fd1, index1, args.local[1], args.peer[1]),
                    _ => return Err(()),
                };
                transmit(fd, index, local, peer, packet.packet()).map_err(|_| ())?;
                state
                    .confirm_sent(packet.slot(), packet.packet())
                    .map_err(|_| ())?;
            }
            println!("R8-ENDPOINT-SENT copies=2 handshake=5 candidate=5 application=2 total=12");
        }
        Mode::Receive => {
            println!("R8-ENDPOINT-LISTENING");
            let (mut state, scid) =
                server_session(&credentials, &fd0, index0, args.local[0], args.peer[0])?;
            let owner = state.issue_profile3_admission_owner(9).map_err(|_| ())?;
            let receiver = manager(
                &credentials,
                SERVER_LOC,
                CLIENT_LOC,
                scid,
                binding(4, args.peer[0]),
                owner,
            )?;
            let update_receive_deadline = deadline_after(Duration::from_secs(5))?;
            let (update, update_binding) = receive_control(
                &fd0,
                index0,
                args.local[0],
                args.peer[0],
                4,
                update_receive_deadline,
            )?;
            let update_now_ms = elapsed_ms(started)?;
            if commit_control(
                &mut state,
                &receiver,
                &update_binding,
                &update,
                update_now_ms,
            )?
            .is_some()
            {
                return Err(());
            }
            let candidate_deadline =
                deadline_at_ms(started, update_now_ms.checked_add(5_000).ok_or(())?)?;
            let (probe, probe_binding) = receive_control(
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                5,
                candidate_deadline,
            )?;
            let challenge_now_ms = elapsed_ms(started)?;
            let challenge = commit_control(
                &mut state,
                &receiver,
                &probe_binding,
                &probe,
                challenge_now_ms,
            )?
            .ok_or(())?;
            let challenge_expiry_ms = match &challenge {
                Control::BindChallenge { expiry_ms, .. } => *expiry_ms,
                _ => return Err(()),
            };
            let challenge_deadline = deadline_at_ms(started, challenge_expiry_ms)?;
            send_control(
                &mut state,
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                &challenge,
            )?;
            let (response, response_binding) = receive_control(
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                5,
                challenge_deadline,
            )?;
            if commit_control(
                &mut state,
                &receiver,
                &response_binding,
                &response,
                elapsed_ms(started)?,
            )?
            .is_some()
            {
                return Err(());
            }
            let mut results = receiver.take_results();
            if results.len() != 1 {
                return Err(());
            }
            let result = results.pop().ok_or(())?;
            send_control(
                &mut state,
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                &result,
            )?;
            let mut admissions = receiver.take_profile3_admissions();
            if admissions.len() != 1 {
                return Err(());
            }
            state
                .activate(admissions.pop().ok_or(())?, 1280)
                .map_err(|_| ())?;
            println!("R8-ENDPOINT-READY handshake=5 candidate=5 application=2 total=12");
            let application_deadline = deadline_after(Duration::from_secs(5))?;
            let (first, first_binding) = receive_control(
                &fd0,
                index0,
                args.local[0],
                args.peer[0],
                4,
                application_deadline,
            )?;
            let (second, second_binding) = receive_control(
                &fd1,
                index1,
                args.local[1],
                args.peer[1],
                5,
                application_deadline,
            )?;
            let one = state
                .inbound(0, &first_binding, &first, elapsed_ms(started)?)
                .map_err(|_| ())?;
            let two = state
                .inbound(1, &second_binding, &second, elapsed_ms(started)?)
                .map_err(|_| ())?;
            if !matches!((one, two), (ReceiveOutcome::Delivered(ref text), ReceiveOutcome::Suppressed) if text.as_slice() == [0x5a; 64])
            {
                return Err(());
            }
            println!("R8-ENDPOINT-PASS delivered=1 suppressed=1 handshake=5 candidate=5 application=2 total=12");
        }
    }
    Ok(())
}

fn main() {
    if let Some(args) = args() {
        if run(args).is_ok() {
            return;
        }
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_uses_a_single_truncation_sentinel() {
        assert_eq!(MAX_FRAME_LEN, 14 + 1280);
    }
    #[test]
    fn client_retry_schedule_uses_absolute_offsets() {
        assert_eq!(control_retry_offset(0).unwrap().as_millis(), 500);
        assert_eq!(control_retry_offset(1).unwrap().as_millis(), 1_500);
        assert_eq!(control_retry_offset(2).unwrap().as_millis(), 3_500);
    }
    #[test]
    fn endpoint_accepts_exact_maximum_frame_but_rejects_an_appended_tail() {
        let local = [1; 6];
        let peer = [2; 6];
        let mut frame = vec![0; MAX_FRAME_LEN];
        frame[..6].copy_from_slice(&local);
        frame[6..12].copy_from_slice(&peer);
        frame[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
        assert_eq!(
            accepted_frame(&frame, frame.len(), local, peer),
            Some(&frame[14..])
        );
        frame.push(0);
        assert_eq!(accepted_frame(&frame, frame.len(), local, peer), None);
    }
}
