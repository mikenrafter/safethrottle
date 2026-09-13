use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::{FutureExt, SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::classify::Classifier;
use crate::config::Config;
use crate::dial::{detect_uplink_iface, dial_tcp, dial_udp};
use crate::dns_cache::DnsCache;
use crate::limiter::{AdmitPhase, AdmitOutcome};
use crate::recovery;
use crate::route;
use crate::sniff;

const TLS_PEEK_TIMEOUT: Duration = Duration::from_millis(1500);
const TLS_PEEK_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
enum HostSource {
    Sni,
    Dns,
    None,
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sni => write!(f, "sni"),
            Self::Dns => write!(f, "dns"),
            Self::None => write!(f, "none"),
        }
    }
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    recovery::ensure_runtime_dir()?;

    if recovery::is_boot_disabled() {
        info!("boot-disabled marker present; staying stopped for remainder of boot");
        recovery::notify("Still disabled for this boot after earlier gateway failures.");
        return Ok(());
    }

    let after_systemd_retry = recovery::is_failed_once();
    let cfg_for_failure = cfg.clone();

    let mut session = match GatewaySession::start(cfg.clone()).await {
        Ok(session) => session,
        Err(err) => {
            match recovery::retry_start_within_budget(
                || GatewaySession::start(cfg.clone()),
                recovery::RECOVERY_BUDGET,
            )
            .await
            {
                Some(session) => session,
                None => {
                    return recovery::handle_recovery_failure(
                        &cfg_for_failure,
                        err,
                        after_systemd_retry,
                    )
                    .await;
                }
            }
        }
    };

    loop {
        let crash_err = session.wait_until_crash().await;
        warn!(error = %crash_err, "gateway stack crashed");

        session = match recovery::retry_start_within_budget(
            || GatewaySession::start(cfg.clone()),
            recovery::RECOVERY_BUDGET,
        )
        .await
        {
            Some(session) => session,
            None => {
                return recovery::handle_recovery_failure(
                    &cfg_for_failure,
                    crash_err,
                    after_systemd_retry,
                )
                .await;
            }
        };
    }
}

struct GatewaySession {
    cancel: CancellationToken,
    crash_rx: Option<oneshot::Receiver<anyhow::Error>>,
}

impl GatewaySession {
    async fn start(cfg: Config) -> anyhow::Result<Self> {
        let cancel = CancellationToken::new();
        let uplink = if cfg.uplink_iface.is_empty() {
            detect_uplink_iface()?
        } else {
            cfg.uplink_iface.clone()
        };
        info!(%uplink, tun = %cfg.tun_name, "starting safethrottle gateway");

        let classifier = Arc::new(Classifier::from_config(&cfg));
        let dns = Arc::new(DnsCache::new(8192));

        let mut tun_cfg = tun::Configuration::default();
        tun_cfg
            .tun_name(&cfg.tun_name)
            .address(cfg.tun_addr.parse::<Ipv4Addr>()?)
            .destination(cfg.tun_dest.parse::<Ipv4Addr>()?)
            .netmask(cfg.tun_netmask.parse::<Ipv4Addr>()?)
            .mtu(1500)
            .up();
        #[cfg(target_os = "linux")]
        tun_cfg.platform_config(|c| {
            c.ensure_root_privileges(true);
        });

        let device = tun::create_as_async(&tun_cfg)?;
        let builder = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .mtu(1500);

        let (stack, runner, udp_socket, tcp_listener) = builder
            .build()
            .map_err(|e| anyhow::anyhow!("stack build: {e}"))?;
        let udp_socket = udp_socket.ok_or_else(|| anyhow::anyhow!("udp disabled"))?;
        let mut tcp_listener = tcp_listener.ok_or_else(|| anyhow::anyhow!("tcp disabled"))?;

        let (crash_tx, crash_rx) = oneshot::channel::<anyhow::Error>();

        if let Some(runner) = runner {
            tokio::spawn(async move {
                let result = AssertUnwindSafe(runner).catch_unwind().await;
                let err = match result {
                    Ok(Ok(())) => anyhow::anyhow!("smoltcp stack runner exited"),
                    Ok(Err(io_err)) => anyhow::anyhow!("smoltcp stack runner I/O error: {io_err}"),
                    Err(payload) => {
                        let msg = recovery::format_panic(payload);
                        error!("smoltcp stack runner panicked: {msg}");
                        anyhow::anyhow!("smoltcp stack runner panicked: {msg}")
                    }
                };
                let _ = crash_tx.send(err);
            });
        } else {
            let _ = crash_tx.send(anyhow::anyhow!("smoltcp stack runner missing"));
        }

        let framed = device.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let bridge_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = bridge_cancel.cancelled() => break,
                    pkt = stack_stream.next() => {
                        match pkt {
                            Some(Ok(pkt)) => {
                                if let Err(e) = tun_sink.send(pkt).await {
                                    warn!("tun send: {e}");
                                }
                            }
                            Some(Err(e)) => warn!("stack stream: {e}"),
                            None => break,
                        }
                    }
                }
            }
        });

        let bridge_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = bridge_cancel.cancelled() => break,
                    pkt = tun_stream.next() => {
                        match pkt {
                            Some(Ok(pkt)) => {
                                if let Err(e) = stack_sink.send(pkt).await {
                                    warn!("stack send: {e}");
                                }
                            }
                            Some(Err(e)) => warn!("tun stream: {e}"),
                            None => break,
                        }
                    }
                }
            }
        });

        if cfg.default_route {
            route::routes_add(&cfg.route_options())?;
            route::mark_active(true)?;
            info!("default route capture enabled");
        }

        let uplink_tcp = uplink.clone();
        let classifier_tcp = classifier.clone();
        let dns_tcp = dns.clone();
        let tcp_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tcp_cancel.cancelled() => break,
                    accepted = tcp_listener.next() => {
                        let Some((stream, local, remote)) = accepted else { break };
                        let uplink = uplink_tcp.clone();
                        let classifier = classifier_tcp.clone();
                        let dns = dns_tcp.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_tcp(stream, local, remote, uplink, classifier, dns).await {
                                debug!(%local, %remote, "tcp session ended: {e}");
                            }
                        });
                    }
                }
            }
        });

        let uplink_udp = uplink.clone();
        let dns_udp = dns.clone();
        let udp_cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = udp_cancel.cancelled() => {}
                _ = handle_udp(udp_socket, uplink_udp, dns_udp) => {}
            }
        });

        info!("gateway running");
        Ok(Self {
            cancel,
            crash_rx: Some(crash_rx),
        })
    }

    async fn wait_until_crash(mut self) -> anyhow::Error {
        match self.crash_rx.take().unwrap().await {
            Ok(err) => err,
            Err(_) => anyhow::anyhow!("crash signal channel closed"),
        }
    }
}

impl Drop for GatewaySession {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn handle_tcp(
    mut client: netstack_smoltcp::TcpStream,
    local: SocketAddr,
    remote: SocketAddr,
    uplink: String,
    classifier: Arc<Classifier>,
    dns: Arc<DnsCache>,
) -> anyhow::Result<()> {
    if remote.port() == 443 || remote.port() == 8443 {
        info!(%local, %remote, "tcp accepted (tls)");
    }

    let (prefix, sni, sni_source) = if remote.port() == 443 || remote.port() == 8443 {
        peek_tls_client_hello(&mut client).await
    } else {
        (Vec::new(), None, HostSource::None)
    };

    let (host, host_source) = if let Some(h) = sni {
        (h, sni_source)
    } else if let Some(h) = dns.lookup(remote.ip()) {
        (h, HostSource::Dns)
    } else {
        (String::new(), HostSource::None)
    };

    if let Some(family) = classifier.match_host(&host) {
        if let Some(lim) = classifier.limiter(family) {
            let grants_before = lim.grants_in_cycle().await;
            let limit = lim.limit().await;
            info!(
                %family,
                %host,
                %remote,
                host_source = %host_source,
                grants = format!("{grants_before}/{limit}"),
                "admit wait begin"
            );

            let outcome = lim.admit().await;
            log_admit_outcome(&family, &host, &remote, &outcome);
        }
    } else if !host.is_empty() {
        debug!(%host, %remote, host_source = %host_source, "passthrough tcp (unmatched host)");
    } else {
        warn!(
            %remote,
            peek_bytes = prefix.len(),
            tls_record_complete = sniff::has_complete_tls_record(&prefix),
            "passthrough tcp (no host — SNI/DNS miss; connection not counted)"
        );
    }

    let mut upstream = match dial_tcp(remote, &uplink).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                %host,
                %remote,
                "upstream dial failed after admit (client may have timed out): {e}"
            );
            return Ok(());
        }
    };
    if !prefix.is_empty() {
        upstream.write_all(&prefix).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let _ = local;
    Ok(())
}

fn log_admit_outcome(
    family: &str,
    host: &str,
    remote: &SocketAddr,
    out: &AdmitOutcome,
) {
    let grants = format!("{}/{}", out.grants_active, out.limit);
    let delay_ms = out.delay.as_millis();
    let window_left_ms = out.window_remaining.as_millis();
    let phase = match out.phase {
        AdmitPhase::Free => "free",
        AdmitPhase::Soft => "soft",
        AdmitPhase::OverflowRollover => "overflow",
    };

    info!(
        %family,
        %host,
        %remote,
        %phase,
        %grants,
        delay_ms,
        window_left_ms,
        "admit granted"
    );

    if out.phase == AdmitPhase::OverflowRollover {
        info!(
            %family,
            %host,
            %remote,
            %grants,
            delay_ms,
            "admit rollover — overflow served in new 60s cycle"
        );
    }
}

/// Read until we have a full TLS record and can extract SNI, or time out.
async fn peek_tls_client_hello(
    client: &mut netstack_smoltcp::TcpStream,
) -> (Vec<u8>, Option<String>, HostSource) {
    let mut buf = Vec::with_capacity(4096);
    let deadline = tokio::time::Instant::now() + TLS_PEEK_TIMEOUT;

    loop {
        if let Some(sni) = sniff::extract_sni(&buf) {
            return (buf, Some(sni), HostSource::Sni);
        }

        if buf.len() >= TLS_PEEK_MAX {
            break;
        }

        if sniff::has_complete_tls_record(&buf) && sniff::extract_sni(&buf).is_none() {
            // Full ClientHello present but no SNI extension.
            break;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let mut tmp = [0u8; 2048];
        match tokio::time::timeout(remaining, client.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) | Err(_) => break,
        }
    }

    let sni = sniff::extract_sni(&buf);
    let source = if sni.is_some() {
        HostSource::Sni
    } else {
        HostSource::None
    };
    (buf, sni, source)
}

async fn handle_udp(
    udp_socket: netstack_smoltcp::UdpSocket,
    uplink: String,
    dns: Arc<DnsCache>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr, SocketAddr)>();
    let (mut read_half, mut write_half) = udp_socket.split();

    tokio::spawn(async move {
        while let Some((data, local, remote)) = rx.recv().await {
            let _ = write_half.send((data, remote, local)).await;
        }
    });

    while let Some((data, local, remote)) = read_half.next().await {
        let tx = tx.clone();
        let uplink = uplink.clone();
        let dns = dns.clone();
        tokio::spawn(async move {
            if remote.port() == 53 || local.port() == 53 {
                dns.learn_from_payload(&data);
            }
            match dial_udp(remote, &uplink).await {
                Ok(sock) => {
                    if let Err(e) = sock.send(&data).await {
                        warn!("udp send: {e}");
                        return;
                    }
                    let mut buf = vec![0u8; 4096];
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                    loop {
                        match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                            Ok(Ok(n)) => {
                                if remote.port() == 53 {
                                    dns.learn_from_payload(&buf[..n]);
                                }
                                let _ = tx.send((buf[..n].to_vec(), local, remote));
                            }
                            _ => break,
                        }
                    }
                }
                Err(e) => warn!(%remote, "udp dial: {e}"),
            }
        });
    }
}

#[allow(dead_code)]
fn _parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}
