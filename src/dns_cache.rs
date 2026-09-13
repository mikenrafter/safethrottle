use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use lru::LruCache;
use tracing::trace;

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    expires: Instant,
}

#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<LruCache<IpAddr, Entry>>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let mut guard = self.inner.lock().ok()?;
        let now = Instant::now();
        match guard.get(&ip) {
            Some(e) if e.expires > now => Some(e.name.clone()),
            Some(_) => {
                guard.pop(&ip);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, ip: IpAddr, name: String, ttl: Duration) {
        let ttl = ttl.max(Duration::from_secs(30)).min(Duration::from_secs(3600));
        if let Ok(mut guard) = self.inner.lock() {
            guard.put(
                ip,
                Entry {
                    name,
                    expires: Instant::now() + ttl,
                },
            );
        }
    }

    /// Parse a DNS message payload and learn A/AAAA → name mappings.
    pub fn learn_from_payload(&self, payload: &[u8]) {
        let msg = match Message::from_vec(payload) {
            Ok(m) => m,
            Err(_) => return,
        };
        for answer in msg.answers() {
            let name = answer.name().to_ascii();
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            let ttl = Duration::from_secs(answer.ttl() as u64);
            match answer.data() {
                RData::A(a) => {
                    let ip = IpAddr::V4(a.0);
                    trace!(%ip, %name, "dns cache insert A");
                    self.insert(ip, name, ttl);
                }
                RData::AAAA(aaaa) => {
                    let ip = IpAddr::V6(aaaa.0);
                    trace!(%ip, %name, "dns cache insert AAAA");
                    self.insert(ip, name, ttl);
                }
                RData::CNAME(_) => {}
                _ => {}
            }
        }
    }
}
