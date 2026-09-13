use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::Config;
use crate::limiter::SoftLimiter;

#[derive(Debug, Clone)]
pub struct Classifier {
    /// Lowercased suffix → family name.
    suffixes: Vec<(String, String)>,
    limiters: BTreeMap<String, SoftLimiter>,
}

impl Classifier {
    pub fn from_config(cfg: &Config) -> Self {
        let window = Duration::from_secs(cfg.window_secs());
        let mut suffixes = Vec::new();
        let mut limiters = BTreeMap::new();

        for (name, fam) in &cfg.families {
            limiters.insert(
                name.clone(),
                SoftLimiter::new(fam.limit, cfg.soft_ratio, cfg.soft_pace, window),
            );
            for s in &fam.suffixes {
                suffixes.push((normalize_host(s), name.clone()));
            }
        }
        // Longer suffixes first so `api.github.com` wins over `github.com` if both listed.
        suffixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { suffixes, limiters }
    }

    pub fn match_host(&self, host: &str) -> Option<&str> {
        let host = normalize_host(host);
        for (suffix, family) in &self.suffixes {
            if host == *suffix || host.ends_with(&format!(".{suffix}")) {
                return Some(family.as_str());
            }
        }
        None
    }

    pub fn limiter(&self, family: &str) -> Option<&SoftLimiter> {
        self.limiters.get(family)
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn matches_site_families() {
        let c = Classifier::from_config(&Config::default_builtin());
        assert_eq!(c.match_host("api.github.com"), Some("github"));
        assert_eq!(c.match_host("raw.githubusercontent.com"), Some("github"));
        assert_eq!(c.match_host("www.youtube.com"), Some("youtube"));
        assert_eq!(c.match_host("r1---sn-abc.googlevideo.com"), Some("youtube"));
        assert_eq!(c.match_host("foo.substack.com"), Some("substack"));
        assert_eq!(c.match_host("example.com"), None);
    }
}
