//! Layer 1 compliance — off-chain sanctions screening of EVM addresses at the
//! official relayer boundaries (shield depositor, unshield recipient, issuer-mint
//! beneficiary). See `docs_internal/privacy-core/compliance-implementation.md`.
//!
//! Design notes that match the doc:
//!   * Pool contracts stay **permissionless** — this gates only the official relayer.
//!   * **Fail-closed**: if every configured provider errors, screening rejects
//!     (there is no on-chain backstop for Layer 1, unlike the Layer 2 frozen root).
//!   * **Off by default** (`SCREENING_ENABLED=false`) so existing e2e / dev flows
//!     are untouched until an operator opts in.
//!   * Providers are reached over plain HTTP/JSON with overridable URLs, which keeps
//!     the decision logic ([`decide`]) a pure, fully unit-testable function and lets
//!     tests point the relayer at a local mock instead of TRM / Chainalysis.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Mutex;

/// Stable client-facing error code for a confirmed sanctions hit (HTTP 403).
pub const SANCTIONED_ADDRESS: &str = "SANCTIONED_ADDRESS";
/// Returned when screening is enabled but cannot reach a verdict and fail-closed
/// is on (HTTP 403) — distinct from an actual sanctions hit so clients can retry.
pub const SCREENING_UNAVAILABLE: &str = "SCREENING_UNAVAILABLE";
/// Enabled screening requires an address at this boundary but none was supplied.
pub const MISSING_SCREENING_ADDRESS: &str = "MISSING_SCREENING_ADDRESS";
/// The supplied value is not a syntactically valid EVM address.
pub const INVALID_ADDRESS: &str = "INVALID_ADDRESS";

/// How verdicts from the two providers are combined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreeningMode {
    /// Either provider flagging the address blocks it (default, strictest).
    Union,
    /// TRM is primary; Chainalysis is consulted only when TRM is unavailable.
    PrimaryFallback,
    /// Chainalysis hard-blocks direct sanctions; TRM adds (future) extra rules.
    /// For v1 direct-sanctions screening this behaves like [`ScreeningMode::Union`].
    Layered,
}

impl ScreeningMode {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "primary_fallback" => Self::PrimaryFallback,
            "layered" => Self::Layered,
            _ => Self::Union,
        }
    }
}

/// Per-provider outcome for one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    /// Provider responded: address is clean.
    Clean,
    /// Provider responded: address is sanctioned.
    Sanctioned,
    /// Provider call failed (network / timeout / bad response).
    Error,
    /// Provider is not configured (no API key) — not consulted.
    Skipped,
}

/// A reason to reject a request at the HTTP boundary.
#[derive(Clone, Debug)]
pub struct ScreenRejection {
    /// Stable machine-readable code (one of the consts above).
    pub code: &'static str,
    /// Human-readable detail (safe to surface to the caller).
    pub message: String,
    /// Suggested HTTP status (403 for policy blocks, 400 for malformed input).
    pub http_status: u16,
}

impl ScreenRejection {
    fn sanctioned(addr: &str, providers: &[&str]) -> Self {
        Self {
            code: SANCTIONED_ADDRESS,
            message: format!("address {addr} is sanctioned (flagged by: {})", providers.join(", ")),
            http_status: 403,
        }
    }
    fn unavailable() -> Self {
        Self {
            code: SCREENING_UNAVAILABLE,
            message: "address screening is unavailable and policy is fail-closed; try again later"
                .to_string(),
            http_status: 403,
        }
    }
    fn missing(boundary: &str) -> Self {
        Self {
            code: MISSING_SCREENING_ADDRESS,
            message: format!("screening is enabled but no address was provided for {boundary}"),
            http_status: 400,
        }
    }
    fn invalid(addr: &str) -> Self {
        Self {
            code: INVALID_ADDRESS,
            message: format!("not a valid EVM address: {addr}"),
            http_status: 400,
        }
    }
}

/// Pure verdict combiner — the heart of the policy, kept side-effect free so it can
/// be exhaustively unit-tested without any network or config.
///
/// Returns `true` to **block**, `false` to **allow**.
pub fn decide(
    mode: ScreeningMode,
    trm: ProviderOutcome,
    chainalysis: ProviderOutcome,
    fail_closed: bool,
) -> Decision {
    use ProviderOutcome::*;
    // Any definitive sanctions hit blocks, regardless of mode (union/layered) — and
    // for primary_fallback a hit from whichever provider actually answered.
    let mut flagged: Vec<&'static str> = Vec::new();
    let primary_answered = matches!(trm, Clean | Sanctioned);

    let consult_chainalysis = match mode {
        ScreeningMode::PrimaryFallback => !primary_answered,
        ScreeningMode::Union | ScreeningMode::Layered => true,
    };

    if matches!(trm, Sanctioned) {
        flagged.push("trm");
    }
    if consult_chainalysis && matches!(chainalysis, Sanctioned) {
        flagged.push("chainalysis");
    }
    if !flagged.is_empty() {
        return Decision::Block { code: SANCTIONED_ADDRESS, providers: flagged };
    }

    // No hit. Decide whether we actually have a trustworthy "clean" verdict.
    let got_clean = match mode {
        ScreeningMode::PrimaryFallback => {
            matches!(trm, Clean) || (!primary_answered && matches!(chainalysis, Clean))
        }
        ScreeningMode::Union | ScreeningMode::Layered => {
            matches!(trm, Clean) || matches!(chainalysis, Clean)
        }
    };

    if got_clean {
        return Decision::Allow;
    }

    // Nobody returned a usable verdict (all Error, or all Skipped). If at least one
    // provider was configured (i.e. not all Skipped) and it errored, fail-closed
    // applies. If NO provider is configured at all, treat as allow (operator opted
    // into "enabled" but configured no keys — degrade to no-op rather than brick).
    let all_skipped = matches!(trm, Skipped) && matches!(chainalysis, Skipped);
    if all_skipped {
        return Decision::Allow;
    }
    if fail_closed {
        Decision::Block { code: SCREENING_UNAVAILABLE, providers: vec![] }
    } else {
        Decision::Allow
    }
}

/// Result of [`decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { code: &'static str, providers: Vec<&'static str> },
}

/// Normalize and validate an EVM address to lowercase `0x` + 40 hex.
pub fn normalize_addr(addr: &str) -> Option<String> {
    let clean = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")).unwrap_or(addr);
    if clean.len() != 40 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", clean.to_ascii_lowercase()))
}

/// Cached verdict for one address: `(stored_at, sanctioned)`.
type CacheEntry = (Instant, bool);

/// Runtime screening configuration + state (cache, HTTP client).
#[derive(Clone)]
pub struct ScreeningConfig {
    pub enabled: bool,
    pub mode: ScreeningMode,
    pub fail_closed: bool,
    trm_api_key: Option<String>,
    chainalysis_api_key: Option<String>,
    trm_url: String,
    chainalysis_url: String,
    timeout: Duration,
    cache_ttl: Duration,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    client: reqwest::Client,
}

impl ScreeningConfig {
    /// Build from environment. All keys are optional; safe (disabled) by default.
    ///
    /// * `SCREENING_ENABLED`        — `true`/`false` (default `false`)
    /// * `SCREENING_MODE`           — `union` | `primary_fallback` | `layered`
    /// * `SCREENING_FAIL_CLOSED`    — default `true`
    /// * `TRM_API_KEY`              — enables TRM provider when set
    /// * `CHAINALYSIS_API_KEY`      — enables Chainalysis provider when set
    /// * `SCREENING_TRM_URL`        — POST endpoint (overridable for tests/mocks)
    /// * `SCREENING_CHAINALYSIS_URL`— GET endpoint base (overridable for tests/mocks)
    /// * `SCREENING_TIMEOUT_MS`     — per-provider timeout (default 4000)
    /// * `SCREENING_CACHE_TTL_SECS` — verdict cache TTL (default 600)
    pub fn from_env() -> Self {
        let enabled = env_bool("SCREENING_ENABLED", false);
        let mode = ScreeningMode::parse(&std::env::var("SCREENING_MODE").unwrap_or_default());
        let fail_closed = env_bool("SCREENING_FAIL_CLOSED", true);
        let timeout_ms = env_u64("SCREENING_TIMEOUT_MS", 4000);
        let cache_ttl_secs = env_u64("SCREENING_CACHE_TTL_SECS", 600);
        let cfg = Self {
            enabled,
            mode,
            fail_closed,
            trm_api_key: non_empty_env("TRM_API_KEY"),
            chainalysis_api_key: non_empty_env("CHAINALYSIS_API_KEY"),
            trm_url: std::env::var("SCREENING_TRM_URL")
                .unwrap_or_else(|_| "https://api.trmlabs.com/public/v2/screening/addresses".into()),
            // Defaults to Chainalysis' free Address Sanctions Screening API (direct
            // OFAC/SDN-aligned sanctions only), which fits the v1 "direct sanctions"
            // policy. Override with the paid KYT/entities endpoint if licensed.
            chainalysis_url: std::env::var("SCREENING_CHAINALYSIS_URL")
                .unwrap_or_else(|_| "https://public.chainalysis.com/api/v1/address".into()),
            timeout: Duration::from_millis(timeout_ms),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: Arc::new(Mutex::new(HashMap::new())),
            client: reqwest::Client::builder().no_proxy().build().unwrap_or_default(),
        };
        if cfg.enabled {
            println!(
                "[screening] ENABLED mode={:?} fail_closed={} trm={} chainalysis={} timeout={}ms cache_ttl={}s",
                cfg.mode,
                cfg.fail_closed,
                cfg.trm_api_key.is_some(),
                cfg.chainalysis_api_key.is_some(),
                timeout_ms,
                cache_ttl_secs,
            );
        }
        cfg
    }

    /// Screen an address that MUST be present when screening is enabled. When
    /// screening is disabled this is a no-op (the optional address is ignored).
    pub async fn screen_required(
        &self,
        addr: Option<&str>,
        boundary: &str,
    ) -> Result<(), ScreenRejection> {
        if !self.enabled {
            return Ok(());
        }
        let addr = addr.ok_or_else(|| ScreenRejection::missing(boundary))?;
        self.screen(addr, boundary).await
    }

    /// Screen an address that is OPTIONAL even when screening is enabled (e.g. an
    /// issuer-mint beneficiary supplied only under some issuer policies). A missing
    /// address is allowed; a present one is screened.
    pub async fn screen_optional(
        &self,
        addr: Option<&str>,
        boundary: &str,
    ) -> Result<(), ScreenRejection> {
        if !self.enabled {
            return Ok(());
        }
        match addr {
            None => Ok(()),
            Some(a) => self.screen(a, boundary).await,
        }
    }

    /// Core screen: normalize, cache lookup, parallel provider calls, [`decide`],
    /// audit log, cache store.
    async fn screen(&self, addr: &str, boundary: &str) -> Result<(), ScreenRejection> {
        let key = normalize_addr(addr).ok_or_else(|| ScreenRejection::invalid(addr))?;

        if let Some(sanctioned) = self.cache_get(&key).await {
            return self.finalize(&key, boundary, sanctioned, &["cache"]);
        }

        let (trm, chainalysis) =
            tokio::join!(self.call_trm(&key), self.call_chainalysis(&key));

        match decide(self.mode, trm, chainalysis, self.fail_closed) {
            Decision::Allow => {
                // Only cache a definitive clean verdict (at least one provider answered).
                if matches!(trm, ProviderOutcome::Clean)
                    || matches!(chainalysis, ProviderOutcome::Clean)
                {
                    self.cache_put(&key, false).await;
                }
                self.audit(&key, boundary, false, &providers_str(trm, chainalysis));
                Ok(())
            }
            Decision::Block { code, providers } => {
                if code == SANCTIONED_ADDRESS {
                    self.cache_put(&key, true).await;
                    self.audit(&key, boundary, true, &providers.join(","));
                    Err(ScreenRejection::sanctioned(&key, &providers))
                } else {
                    // Unavailable / fail-closed — do not cache (it may recover).
                    self.audit(&key, boundary, true, "unavailable");
                    Err(ScreenRejection::unavailable())
                }
            }
        }
    }

    fn finalize(
        &self,
        addr: &str,
        boundary: &str,
        sanctioned: bool,
        providers: &[&str],
    ) -> Result<(), ScreenRejection> {
        self.audit(addr, boundary, sanctioned, &providers.join(","));
        if sanctioned {
            Err(ScreenRejection::sanctioned(addr, providers))
        } else {
            Ok(())
        }
    }

    async fn cache_get(&self, key: &str) -> Option<bool> {
        let mut cache = self.cache.lock().await;
        if let Some((at, sanctioned)) = cache.get(key).copied() {
            if at.elapsed() < self.cache_ttl {
                return Some(sanctioned);
            }
            cache.remove(key);
        }
        None
    }

    async fn cache_put(&self, key: &str, sanctioned: bool) {
        self.cache.lock().await.insert(key.to_string(), (Instant::now(), sanctioned));
    }

    /// Audit trail (doc §"Screening module behavior" step 5). Stdout keeps it in the
    /// container log stream; operators can ship it to a retained store.
    fn audit(&self, addr: &str, boundary: &str, blocked: bool, providers: &str) {
        println!(
            "[screening][audit] ts={} addr={} boundary={} blocked={} providers={}",
            now_unix(),
            addr,
            boundary,
            blocked,
            providers,
        );
    }

    async fn call_trm(&self, addr: &str) -> ProviderOutcome {
        let Some(key) = self.trm_api_key.as_deref() else { return ProviderOutcome::Skipped };
        let body = serde_json::json!([{ "address": addr, "chain": "ethereum" }]);
        let req = self
            .client
            .post(&self.trm_url)
            .basic_auth(key, Some(key))
            .json(&body)
            .timeout(self.timeout)
            .send();
        match req.await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(v) => {
                    if trm_is_sanctioned(&v) {
                        ProviderOutcome::Sanctioned
                    } else {
                        ProviderOutcome::Clean
                    }
                }
                Err(e) => {
                    eprintln!("[screening] TRM parse error: {e}");
                    ProviderOutcome::Error
                }
            },
            Err(e) => {
                eprintln!("[screening] TRM request error: {e}");
                ProviderOutcome::Error
            }
        }
    }

    async fn call_chainalysis(&self, addr: &str) -> ProviderOutcome {
        let Some(key) = self.chainalysis_api_key.as_deref() else { return ProviderOutcome::Skipped };
        let url = format!("{}/{}", self.chainalysis_url.trim_end_matches('/'), addr);
        let req = self
            .client
            .get(&url)
            .header("X-API-Key", key)
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .send();
        match req.await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(v) => {
                    if chainalysis_is_sanctioned(&v) {
                        ProviderOutcome::Sanctioned
                    } else {
                        ProviderOutcome::Clean
                    }
                }
                Err(e) => {
                    eprintln!("[screening] Chainalysis parse error: {e}");
                    ProviderOutcome::Error
                }
            },
            Err(e) => {
                eprintln!("[screening] Chainalysis request error: {e}");
                ProviderOutcome::Error
            }
        }
    }
}

/// TRM v2 Wallet Screening response: any risk indicator/entity with category
/// "sanctions" (or a sanctioned-ownership signal) is a direct sanctions hit. The
/// live API returns camelCase (`addressRiskIndicators`, `riskType`); aliases also
/// accept snake_case so a self-hosted gateway / mock can use either.
fn trm_is_sanctioned(v: &serde_json::Value) -> bool {
    #[derive(Deserialize)]
    struct Entry {
        #[serde(default, rename = "addressRiskIndicators", alias = "address_risk_indicators")]
        address_risk_indicators: Vec<RiskIndicator>,
        #[serde(default, rename = "riskIndicators", alias = "risk_indicators")]
        risk_indicators: Vec<RiskIndicator>,
        #[serde(default)]
        entities: Vec<RiskIndicator>,
    }
    #[derive(Deserialize)]
    struct RiskIndicator {
        #[serde(default)]
        category: String,
        #[serde(default, rename = "riskType", alias = "risk_type")]
        risk_type: String,
    }
    let is_hit = |r: &RiskIndicator| {
        r.category.eq_ignore_ascii_case("sanctions") || r.risk_type.eq_ignore_ascii_case("ownership")
    };
    let entry_hit = |e: &Entry| {
        e.address_risk_indicators.iter().any(is_hit)
            || e.risk_indicators.iter().any(is_hit)
            || e.entities.iter().any(is_hit)
    };
    // The API returns an array (one element per queried address).
    if let Ok(list) = serde_json::from_value::<Vec<Entry>>(v.clone()) {
        return list.iter().any(entry_hit);
    }
    if let Ok(e) = serde_json::from_value::<Entry>(v.clone()) {
        return entry_hit(&e);
    }
    false
}

/// Chainalysis Address Sanctions Screening response. The free Sanctions API returns
/// `{ "identifications": [ { "category": "sanctions", ... } ] }` (empty = clean);
/// the paid entities/KYT shapes (`sanctions[]`, `addressIdentifications[]`) are also
/// accepted so the endpoint can be swapped without code changes.
fn chainalysis_is_sanctioned(v: &serde_json::Value) -> bool {
    let has_sanctions_category = |arr: &[serde_json::Value]| {
        arr.iter().any(|i| {
            i.get("category")
                .and_then(|c| c.as_str())
                .map(|c| c.eq_ignore_ascii_case("sanctions"))
                .unwrap_or(false)
        })
    };
    if let Some(arr) = v.get("identifications").and_then(|s| s.as_array()) {
        if has_sanctions_category(arr) {
            return true;
        }
    }
    if let Some(arr) = v.get("addressIdentifications").and_then(|s| s.as_array()) {
        if has_sanctions_category(arr) {
            return true;
        }
    }
    if let Some(arr) = v.get("sanctions").and_then(|s| s.as_array()) {
        if !arr.is_empty() {
            return true;
        }
    }
    false
}

fn providers_str(trm: ProviderOutcome, chainalysis: ProviderOutcome) -> String {
    format!("trm={trm:?},chainalysis={chainalysis:?}")
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProviderOutcome::*;

    fn blocked(d: &Decision) -> bool {
        matches!(d, Decision::Block { .. })
    }

    #[test]
    fn normalize_accepts_valid_and_lowercases() {
        assert_eq!(
            normalize_addr("0xABCD000000000000000000000000000000001234"),
            Some("0xabcd000000000000000000000000000000001234".to_string())
        );
        assert_eq!(
            normalize_addr("ABCD000000000000000000000000000000001234"),
            Some("0xabcd000000000000000000000000000000001234".to_string())
        );
    }

    #[test]
    fn normalize_rejects_malformed() {
        assert_eq!(normalize_addr("0x1234"), None);
        assert_eq!(normalize_addr("0xZZ..."), None);
        assert_eq!(normalize_addr(""), None);
    }

    #[test]
    fn union_blocks_on_either_hit() {
        assert!(blocked(&decide(ScreeningMode::Union, Sanctioned, Clean, true)));
        assert!(blocked(&decide(ScreeningMode::Union, Clean, Sanctioned, true)));
        assert_eq!(decide(ScreeningMode::Union, Clean, Clean, true), Decision::Allow);
    }

    #[test]
    fn union_clean_when_one_clean_one_error() {
        assert_eq!(decide(ScreeningMode::Union, Clean, Error, true), Decision::Allow);
        assert_eq!(decide(ScreeningMode::Union, Error, Clean, true), Decision::Allow);
    }

    #[test]
    fn fail_closed_blocks_when_all_error() {
        let d = decide(ScreeningMode::Union, Error, Error, true);
        assert!(matches!(d, Decision::Block { code, .. } if code == SCREENING_UNAVAILABLE));
    }

    #[test]
    fn fail_open_allows_when_all_error() {
        assert_eq!(decide(ScreeningMode::Union, Error, Error, false), Decision::Allow);
    }

    #[test]
    fn all_skipped_allows_regardless_of_fail_closed() {
        // Enabled but no providers configured: degrade to no-op rather than brick.
        assert_eq!(decide(ScreeningMode::Union, Skipped, Skipped, true), Decision::Allow);
    }

    #[test]
    fn primary_fallback_uses_chainalysis_only_when_trm_silent() {
        // TRM answered clean → Chainalysis (even sanctioned) is NOT consulted.
        assert_eq!(
            decide(ScreeningMode::PrimaryFallback, Clean, Sanctioned, true),
            Decision::Allow
        );
        // TRM errored → fall back to Chainalysis.
        assert!(blocked(&decide(ScreeningMode::PrimaryFallback, Error, Sanctioned, true)));
        assert_eq!(decide(ScreeningMode::PrimaryFallback, Error, Clean, true), Decision::Allow);
        // Both unavailable → fail-closed.
        assert!(blocked(&decide(ScreeningMode::PrimaryFallback, Error, Error, true)));
    }

    #[test]
    fn layered_behaves_like_union_for_direct_sanctions() {
        assert!(blocked(&decide(ScreeningMode::Layered, Clean, Sanctioned, true)));
        assert!(blocked(&decide(ScreeningMode::Layered, Sanctioned, Skipped, true)));
    }

    #[test]
    fn trm_parser_detects_sanctions_category() {
        // Live TRM camelCase shape.
        let v = serde_json::json!([{ "addressRiskIndicators": [{ "category": "Sanctions" }] }]);
        assert!(trm_is_sanctioned(&v));
        // snake_case alias (mock / gateway) still works.
        let alias = serde_json::json!([{ "risk_indicators": [{ "category": "Sanctions" }] }]);
        assert!(trm_is_sanctioned(&alias));
        // Ownership riskType counts as a direct sanctions hit.
        let owned = serde_json::json!([{ "entities": [{ "riskType": "OWNERSHIP" }] }]);
        assert!(trm_is_sanctioned(&owned));
        let clean = serde_json::json!([{ "addressRiskIndicators": [{ "category": "Gambling" }] }]);
        assert!(!trm_is_sanctioned(&clean));
    }

    #[test]
    fn chainalysis_parser_detects_sanctions() {
        // Free Sanctions API shape.
        let free = serde_json::json!({ "identifications": [{ "category": "sanctions", "name": "OFAC SDN" }] });
        assert!(chainalysis_is_sanctioned(&free));
        // Paid/alternate shapes.
        let id = serde_json::json!({ "addressIdentifications": [{ "category": "sanctions" }] });
        assert!(chainalysis_is_sanctioned(&id));
        let kyt = serde_json::json!({ "sanctions": [{ "name": "OFAC SDN" }] });
        assert!(chainalysis_is_sanctioned(&kyt));
        // Clean = empty identifications.
        let clean = serde_json::json!({ "identifications": [] });
        assert!(!chainalysis_is_sanctioned(&clean));
    }

    #[test]
    fn mode_parse_defaults_to_union() {
        assert_eq!(ScreeningMode::parse("union"), ScreeningMode::Union);
        assert_eq!(ScreeningMode::parse("primary_fallback"), ScreeningMode::PrimaryFallback);
        assert_eq!(ScreeningMode::parse("layered"), ScreeningMode::Layered);
        assert_eq!(ScreeningMode::parse("garbage"), ScreeningMode::Union);
    }

    /// End-to-end: stand up a mock TRM endpoint, point the relayer's screening config
    /// at it via env, and verify the disabled→no-op and enabled→block/allow paths.
    /// This is the ONLY test that touches process env (kept as a single test so it
    /// cannot race the pure, env-free unit tests above).
    #[tokio::test]
    async fn screen_end_to_end_via_mock_provider() {
        use axum::{routing::post, Json, Router};

        let sanctioned = "0xdead000000000000000000000000000000000001";
        let clean = "0x1111111111111111111111111111111111111111";

        // ── Disabled (default): never calls a provider, always allows. ──
        std::env::remove_var("SCREENING_ENABLED");
        let off = ScreeningConfig::from_env();
        assert!(off.screen_required(Some(sanctioned), "x").await.is_ok());
        assert!(off.screen_required(None, "x").await.is_ok());

        // Mock provider: flag any address containing "dead" as sanctioned.
        async fn mock_trm(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
            let addr = body
                .as_array()
                .and_then(|a| a.first())
                .and_then(|e| e.get("address"))
                .and_then(|a| a.as_str())
                .unwrap_or_default()
                .to_string();
            let category = if addr.contains("dead") { "sanctions" } else { "gambling" };
            Json(serde_json::json!([{ "risk_indicators": [{ "category": category }] }]))
        }
        let app = Router::new().route("/screen", post(mock_trm));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // ── Enabled, pointed at the mock. ──
        std::env::set_var("SCREENING_ENABLED", "true");
        std::env::set_var("SCREENING_TRM_URL", format!("http://{addr}/screen"));
        std::env::set_var("TRM_API_KEY", "test-key");
        std::env::remove_var("CHAINALYSIS_API_KEY");
        std::env::set_var("SCREENING_FAIL_CLOSED", "true");
        let cfg = ScreeningConfig::from_env();

        let blocked = cfg.screen_required(Some(sanctioned), "shield_depositor").await;
        assert!(matches!(&blocked, Err(r) if r.code == SANCTIONED_ADDRESS && r.http_status == 403));

        let allowed = cfg.screen_required(Some(clean), "shield_depositor").await;
        assert!(allowed.is_ok(), "clean address should pass: {allowed:?}");

        // Cache hit returns the same verdict.
        let blocked_again = cfg.screen_required(Some(sanctioned), "shield_depositor").await;
        assert!(matches!(&blocked_again, Err(r) if r.code == SANCTIONED_ADDRESS));

        // Enabled but no address → 400 MISSING_SCREENING_ADDRESS.
        let missing = cfg.screen_required(None, "shield_depositor").await;
        assert!(matches!(&missing, Err(r) if r.code == MISSING_SCREENING_ADDRESS && r.http_status == 400));

        // Optional screening with no address is a no-op even when enabled.
        assert!(cfg.screen_optional(None, "mint_beneficiary").await.is_ok());

        std::env::remove_var("SCREENING_ENABLED");
        std::env::remove_var("SCREENING_TRM_URL");
        std::env::remove_var("TRM_API_KEY");
        std::env::remove_var("SCREENING_FAIL_CLOSED");
    }
}
