use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex as SyncMutex, RwLock as SyncRwLock},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    config::{AllowEntry, validated_api_base},
    github::{Device, Identity},
    journal::{Journal, SessionEvent},
    passkeys::{CeremonyState, Passkeys},
};

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    provider: String,
    #[serde(default)]
    authentication: String,
    #[serde(default)]
    max_ttl: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub service_account: String,
    #[serde(default)]
    totp_secret_file: PathBuf,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_id_file: PathBuf,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    client_secret_file: PathBuf,
    #[serde(default)]
    allowed_user_ids: Vec<i64>,
    #[serde(default)]
    allowed_user_ids_file: PathBuf,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    api_base_url: String,
    pub passkey_credentials: Option<Vec<String>>,
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        if self.provider == "kubernetes" {
            ensure!(
                valid_kubernetes_name(&self.namespace)
                    && valid_kubernetes_name(&self.service_account),
                "invalid emergency Kubernetes namespace or service account"
            );
        }
        match (self.provider.as_str(), self.authentication()) {
            ("kubernetes", "totp") => {
                let secret = Zeroizing::new(
                    std::fs::read_to_string(&self.totp_secret_file).context("read TOTP secret")?,
                );
                decode_totp_secret(&secret)?;
            }
            ("github_user" | "kubernetes", "github_device") => {
                ensure!(
                    validated_api_base(&self.api_base_url)?.as_str() == "https://api.github.com/",
                    "github_device requires the github.com REST API"
                );
                ensure!(
                    !self.scopes.is_empty()
                        && self.scopes.iter().all(|scope| !scope.is_empty()
                            && !scope.contains(',')
                            && !scope.chars().any(char::is_whitespace)),
                    "GitHub scopes are required"
                );
                self.identity()?;
            }
            ("approval", "webauthn") => {
                ensure!(
                    self.namespace.is_empty() && self.service_account.is_empty(),
                    "approval cannot issue Kubernetes credentials"
                );
            }
            ("kubernetes", "webauthn") => (),
            _ => anyhow::bail!("unsupported emergency provider or authentication method"),
        }
        if let Some(ids) = &self.passkey_credentials {
            let mut unique = std::collections::BTreeSet::new();
            ensure!(
                self.uses_passkeys()
                    && !ids.is_empty()
                    && ids.iter().all(|id| HEXLOWER
                        .decode(id.as_bytes())
                        .is_ok_and(|bytes| bytes.len() == 32)
                        && unique.insert(id)),
                "invalid or duplicate passkey credential ID"
            );
        }
        self.ttl()?;
        Ok(())
    }

    pub fn uses_passkeys(&self) -> bool {
        self.authentication() == "webauthn"
    }
    pub fn is_approval(&self) -> bool {
        self.provider == "approval" && self.uses_passkeys()
    }

    pub fn api_base(&self) -> Result<reqwest::Url> {
        validated_api_base(&self.api_base_url)
    }

    pub fn identity(&self) -> Result<Identity> {
        Identity::load(
            &self.client_id,
            &self.client_id_file,
            &self.client_secret,
            &self.client_secret_file,
            &self.allowed_user_ids,
            &self.allowed_user_ids_file,
        )
    }

    fn authentication(&self) -> &str {
        if self.authentication.is_empty() {
            if self.provider == "github_user" {
                "github_device"
            } else {
                "totp"
            }
        } else {
            &self.authentication
        }
    }

    fn ttl(&self) -> Result<Duration> {
        if self.max_ttl.is_empty() {
            return Ok(Duration::from_secs(if self.is_approval() {
                3600
            } else {
                900
            }));
        }
        let ttl = humantime::parse_duration(&self.max_ttl)?;
        ensure!(
            !ttl.is_zero()
                && (!self.is_approval() || ttl >= Duration::from_secs(300))
                && ttl
                    <= Duration::from_secs(if self.provider == "github_user" {
                        5400
                    } else {
                        3600
                    }),
            "invalid max_ttl"
        );
        Ok(ttl)
    }
}

fn valid_kubernetes_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            let alnum = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
            bytes.first().is_some_and(alnum)
                && bytes.last().is_some_and(alnum)
                && bytes.iter().all(|byte| alnum(byte) || *byte == b'-')
        })
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    AwaitingTotp,
    AwaitingGithub,
    AwaitingPasskey,
    Invalidated,
    Active,
    RevocationPending,
    Expired,
    Revoked,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            Self::AwaitingTotp => "awaiting_totp",
            Self::AwaitingGithub => "awaiting_github",
            Self::AwaitingPasskey => "awaiting_passkey",
            Self::Invalidated => "invalidated",
            Self::Active => "active",
            Self::RevocationPending => "revocation_pending",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct PublicSession {
    id: String,
    profile: String,
    provider: String,
    authentication: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_label: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    approval_used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_code: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    state: State,
    expires_at: DateTime<Utc>,
}

pub struct Session {
    public: PublicSession,
    pub definition: Profile,
    pub owner: String,
    pub bound_secret: Option<String>,
    pending_logged: bool,
    invalidation_pending: bool,
    pub access_token: Option<Zeroizing<String>>,
    pub device: Option<Device>,
    requested_ttl: Duration,
}

impl Session {
    pub fn id(&self) -> &str {
        &self.public.id
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.public.expires_at
    }
    pub fn active(&self) -> bool {
        self.public.state == State::Active && self.expires_at() > Utc::now()
    }

    fn record(&self, journal: &Journal, state: State, event: &str) -> Result<()> {
        journal.record(SessionEvent {
            subject: &self.owner,
            kind: event,
            id: self.id(),
            profile: &self.public.profile,
            provider: &self.public.provider,
            state: state.name(),
            expires: self.expires_at().timestamp_millis(),
            approval_digest: self.public.approval_digest.as_deref(),
        })
    }

    pub fn approval(&self) -> bool {
        self.definition.is_approval()
    }

    pub fn approval_matches(&self, profile: &str, digest: &str, label: &str) -> bool {
        self.approval()
            && self.active()
            && self.public.profile == profile
            && self.public.approval_digest.as_deref() == Some(digest)
            && self.public.approval_label.as_deref() == Some(label)
    }

    pub fn approval_used(&self) -> bool {
        self.public.approval_used
    }

    pub fn redeem(&mut self, journal: &Journal, digest: &str) -> Result<()> {
        ensure!(
            self.approval()
                && self.active()
                && !self.approval_used()
                && self.public.approval_digest.as_deref() == Some(digest),
            "approval is unavailable"
        );
        self.record(journal, State::Active, "approval.redeemed")?;
        self.public.approval_used = true;
        Ok(())
    }

    pub fn github(&self) -> bool {
        self.public.provider == "github_user"
    }

    pub fn expected_scopes(&self) -> Vec<String> {
        let mut scopes = if self.public.scopes.is_empty() {
            self.definition.scopes.clone()
        } else {
            self.public.scopes.clone()
        };
        scopes.sort_unstable();
        scopes.dedup();
        scopes
    }

    pub fn publish(&mut self, journal: &Journal, approved: bool, expired: bool) -> Result<()> {
        let (state, event) = match (approved, expired) {
            (true, _) => (State::Active, "session.activated"),
            (false, true) => (State::Expired, "session.expired"),
            (false, false) => (State::Invalidated, "session.invalidated"),
        };
        if !approved {
            self.public.state = state;
        }
        self.record(journal, state, event)?;
        self.public.state = state;
        self.device = None;
        Ok(())
    }

    pub fn expire_if_due(&mut self, journal: &Journal) -> Result<bool> {
        if matches!(
            self.public.state,
            State::Revoked | State::Expired | State::Invalidated | State::RevocationPending
        ) || self.expires_at() > Utc::now()
        {
            return Ok(false);
        }
        self.record(journal, State::Expired, "session.expired")?;
        self.public.state = State::Expired;
        self.device = None;
        self.access_token = None;
        Ok(true)
    }

    pub fn public(&self) -> PublicSession {
        self.public.clone()
    }

    pub fn begin_revoke(&mut self, journal: &Journal) -> Result<()> {
        if matches!(
            self.public.state,
            State::Revoked | State::Expired | State::Invalidated
        ) {
            return Ok(());
        }
        self.public.state = State::RevocationPending;
        if !self.pending_logged {
            self.record(
                journal,
                State::RevocationPending,
                "session.revocation_pending",
            )?;
            self.pending_logged = true;
        }
        Ok(())
    }

    pub fn finish_revoke(&mut self, journal: &Journal) -> Result<()> {
        if !matches!(
            self.public.state,
            State::Revoked | State::Expired | State::Invalidated
        ) {
            self.record(journal, State::Revoked, "session.revoked")?;
            self.public.state = State::Revoked;
        }
        Ok(())
    }
}

struct Entry {
    owner: String,
    session: Arc<Mutex<Session>>,
}
type Sessions = HashMap<String, Entry>;

struct Creation<'a> {
    pending: &'a SyncMutex<HashMap<String, String>>,
    id: String,
}

impl Drop for Creation<'_> {
    fn drop(&mut self) {
        self.pending
            .lock()
            .expect("pending session lock")
            .remove(&self.id);
    }
}

pub struct Emergency {
    profiles: SyncRwLock<BTreeMap<String, Profile>>,
    sessions: Mutex<Sessions>,
    journal: Journal,
    github: reqwest::Client,
    creating: SyncMutex<HashMap<String, String>>,
    passkeys: Option<Passkeys>,
    ceremonies: Mutex<HashMap<String, Ceremony>>,
}

struct Ceremony {
    owner: String,
    session: String,
    label: String,
    expires: DateTime<Utc>,
    options: serde_json::Value,
    state: CeremonyState,
}

#[derive(Deserialize)]
pub struct CreateSession {
    pub profile: String,
    pub ttl_seconds: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub approval_digest: String,
    #[serde(default)]
    pub approval_label: String,
}

// Go clients encode an omitted scope request as a null JSON slice.
fn deserialize_scopes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    Option::<Vec<String>>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn label_control(ch: char) -> bool {
    ch.is_control()
        || matches!(ch as u32, 0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
}

impl Emergency {
    pub fn new(
        profiles: BTreeMap<String, Profile>,
        journal: Journal,
        passkeys: Option<Passkeys>,
    ) -> Result<Self> {
        Ok(Self {
            profiles: SyncRwLock::new(profiles),
            sessions: Mutex::default(),
            journal,
            github: crate::github::client()?,
            creating: SyncMutex::default(),
            passkeys,
            ceremonies: Mutex::default(),
        })
    }

    pub fn profiles(
        &self,
        allowlist: &[AllowEntry],
        subject: &str,
    ) -> Result<Vec<serde_json::Value>> {
        self.profiles.read().expect("emergency profile lock")
            .iter()
            .filter(|(name, _)| allowed(allowlist, subject, name))
            .map(|(name, profile)| {
                Ok(serde_json::json!({
                    "name": name, "provider": profile.provider, "authentication": profile.authentication(),
                    "max_ttl_seconds": profile.ttl()?.as_secs(),
                }))
            })
            .collect()
    }

    pub fn github_client(&self) -> &reqwest::Client {
        &self.github
    }

    pub async fn create(
        &self,
        allowlist: &[AllowEntry],
        subject: String,
        request: CreateSession,
    ) -> Result<PublicSession> {
        let CreateSession {
            profile,
            ttl_seconds,
            mut scopes,
            approval_digest,
            approval_label,
        } = request;
        let definition = self
            .profiles
            .read()
            .expect("emergency profile lock")
            .get(&profile)
            .filter(|_| allowed(allowlist, &subject, &profile))
            .context("emergency profile is unavailable")?
            .clone();
        ensure!(
            scopes.is_empty() || definition.provider == "github_user",
            "scope restrictions require a GitHub user profile"
        );
        ensure!(
            scopes
                .iter()
                .all(|scope| !scope.is_empty() && definition.scopes.contains(scope)),
            "requested scope is not allowed by the emergency profile"
        );
        scopes.sort_unstable();
        scopes.dedup();
        let max = definition.ttl()?;
        let is_approval = definition.is_approval();
        ensure!(
            is_approval != approval_digest.is_empty(),
            "approval profile and bound request are required together"
        );
        let ttl = if is_approval {
            ensure!(
                approval_digest.len() == 64
                    && approval_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !approval_label.trim().is_empty()
                    && approval_label.len() <= 3000
                    && !approval_label.chars().any(label_control),
                "approval requires a SHA-256 digest and a review label"
            );
            let requested = ttl_seconds.unwrap_or(300);
            ensure!(
                (300..=3600).contains(&requested),
                "approval TTL must be between five minutes and one hour"
            );
            let ttl = Duration::from_secs(requested as u64);
            ensure!(ttl <= max, "approval TTL exceeds the profile maximum");
            ttl
        } else {
            ttl_seconds
                .filter(|ttl| *ttl > 0)
                .map_or(max, |ttl| Duration::from_secs(ttl as u64).min(max))
        };
        let expires_at = Utc::now() + chrono::Duration::from_std(ttl)?;
        self.prune().await?;
        let id = format!("E-{}", random_id(18)?);
        let creation = {
            let registry = self.sessions.lock().await;
            let mut pending = self.creating.lock().expect("pending session lock");
            let subject_count = registry
                .values()
                .filter(|entry| entry.owner == subject)
                .count()
                + pending.values().filter(|owner| *owner == &subject).count();
            ensure!(
                subject_count < 16 && registry.len() + pending.len() < 1024,
                "emergency session capacity reached"
            );
            pending.insert(id.clone(), subject.clone());
            Creation {
                pending: &self.creating,
                id: id.clone(),
            }
        };
        let github = definition.authentication() == "github_device";
        let device = async {
            if github {
                let requested = if scopes.is_empty() {
                    &definition.scopes
                } else {
                    &scopes
                };
                return Device::start(&self.github, &definition.identity()?, requested)
                    .await
                    .map(Some);
            }
            Ok::<_, anyhow::Error>(None)
        }
        .await;
        let device = device?;
        ensure!(
            expires_at > Utc::now(),
            "emergency session expired during creation"
        );
        let mut verification_uri = device
            .as_ref()
            .map(|device| device.verification_uri.clone());
        let challenge = if definition.uses_passkeys() {
            let passkeys = self.passkeys.as_ref().context("passkeys are unavailable")?;
            let token = format!("E-{}", random_id(18)?);
            let (options, state) =
                passkeys.begin_authentication(definition.passkey_credentials.as_deref())?;
            verification_uri = Some(passkeys.ceremony_url(&token));
            let expires = if is_approval {
                expires_at
            } else {
                expires_at.min(Utc::now() + chrono::Duration::minutes(5))
            };
            Some((
                token,
                Ceremony {
                    owner: subject.clone(),
                    session: id.clone(),
                    label: String::new(),
                    expires,
                    options,
                    state,
                },
            ))
        } else {
            None
        };
        let state = if github {
            State::AwaitingGithub
        } else if challenge.is_some() {
            State::AwaitingPasskey
        } else {
            State::AwaitingTotp
        };
        let public = PublicSession {
            id: id.clone(),
            profile,
            provider: definition.provider.clone(),
            authentication: definition.authentication().into(),
            state,
            expires_at,
            verification_uri,
            approval_digest: is_approval.then_some(approval_digest),
            approval_label: is_approval.then_some(approval_label),
            approval_used: false,
            user_code: device.as_ref().map(|device| device.user_code.clone()),
            scopes,
        };
        let session = Session {
            public: public.clone(),
            owner: subject,
            definition,
            bound_secret: None,
            pending_logged: false,
            invalidation_pending: false,
            access_token: None,
            device,
            requested_ttl: ttl,
        };
        let mut ceremonies = self.ceremonies.lock().await;
        if let Some((_, ceremony)) = &challenge {
            Self::check_ceremony_capacity(&mut ceremonies, &ceremony.owner)?;
        }
        let mut registry = self.sessions.lock().await;
        session.record(&self.journal, state, "session.created")?;
        if let Some((token, challenge)) = challenge {
            ceremonies.insert(token, challenge);
        }
        registry.insert(
            id,
            Entry {
                owner: session.owner.clone(),
                session: Arc::new(Mutex::new(session)),
            },
        );
        drop(creation);
        Ok(public)
    }

    pub async fn owned(
        &self,
        subject: &str,
        id: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<Session>> {
        let entry = self
            .sessions
            .lock()
            .await
            .get(id)
            .filter(|entry| entry.owner == subject)
            .map(|entry| entry.session.clone())
            .context("emergency session is unavailable")?;
        let session = entry.lock_owned().await;
        ensure!(session.owner == subject, "emergency session is unavailable");
        Ok(session)
    }

    pub async fn verify(&self, subject: &str, id: &str, code: &str) -> Result<PublicSession> {
        let mut session = self.owned(subject, id).await?;
        let now = Utc::now();
        ensure!(
            session.public.state == State::AwaitingTotp && session.expires_at() > now,
            "session is not awaiting TOTP"
        );
        let secret = Zeroizing::new(
            tokio::fs::read_to_string(&session.definition.totp_secret_file)
                .await
                .context("read TOTP secret")?,
        );
        verify_totp(&self.journal, &secret, code, now.timestamp())?;
        ensure!(
            session.expires_at() > Utc::now(),
            "session is not awaiting TOTP"
        );
        session.record(&self.journal, State::Active, "session.activated")?;
        session.public.state = State::Active;
        Ok(session.public.clone())
    }

    fn check_ceremony_capacity(
        ceremonies: &mut HashMap<String, Ceremony>,
        subject: &str,
    ) -> Result<()> {
        ceremonies.retain(|_, ceremony| ceremony.expires > Utc::now());
        ensure!(
            ceremonies.len() < 1024
                && ceremonies
                    .values()
                    .filter(|ceremony| ceremony.owner == subject)
                    .count()
                    < 16,
            "passkey ceremony capacity reached"
        );
        Ok(())
    }

    pub async fn begin_enrollment(
        &self,
        subject: &str,
        id: &str,
        label: &str,
    ) -> Result<serde_json::Value> {
        let label = label.trim();
        ensure!(
            label.len() <= 128 && !label.chars().any(label_control),
            "invalid passkey label"
        );
        let passkeys = self.passkeys.as_ref().context("passkeys are unavailable")?;
        let proof = self.owned(subject, id).await?;
        ensure!(
            proof.active() && proof.public.authentication == "totp",
            "an active TOTP-authenticated session is required"
        );
        let token = format!("E-{}", random_id(18)?);
        let enrollment = format!("E-{}", random_id(18)?);
        let (options, state) = passkeys.begin_registration()?;
        let expires = proof
            .expires_at()
            .min(Utc::now() + chrono::Duration::minutes(5));
        let ceremony = Ceremony {
            owner: subject.into(),
            session: id.into(),
            label: label.into(),
            expires,
            options,
            state,
        };
        let mut ceremonies = self.ceremonies.lock().await;
        Self::check_ceremony_capacity(&mut ceremonies, subject)?;
        ceremonies.insert(token.clone(), ceremony);
        Ok(
            serde_json::json!({"id":enrollment,"state":"awaiting_passkey",
            "verification_uri":passkeys.ceremony_url(&token),"expires_at":expires}),
        )
    }

    pub async fn ceremony_options(&self, subject: &str, token: &str) -> Result<serde_json::Value> {
        let (id, options, registration, expires) = {
            let ceremonies = self.ceremonies.lock().await;
            let ceremony = ceremonies
                .get(token)
                .filter(|entry| entry.owner == subject && entry.expires > Utc::now())
                .context("passkey ceremony not found or expired")?;
            (
                ceremony.session.clone(),
                ceremony.options.clone(),
                matches!(ceremony.state, CeremonyState::Registration(_)),
                ceremony.expires,
            )
        };
        let session = self.owned(subject, &id).await?;
        let mut value = serde_json::json!({"kind":if registration { "registration" } else { "authentication" }, "public_key":options});
        if registration {
            ensure!(
                session.active(),
                "passkey enrollment proof is no longer active"
            );
        } else {
            ensure!(
                session.public.state == State::AwaitingPasskey && expires > Utc::now(),
                "passkey ceremony not found or expired"
            );
            if session.approval() {
                value["approval_label"] = serde_json::json!(session.public.approval_label);
                value["expires_at"] = serde_json::json!(session.expires_at());
            }
        }
        Ok(value)
    }

    pub async fn verify_passkey(
        &self,
        subject: &str,
        token: &str,
        response: &[u8],
        minutes: Option<i64>,
    ) -> Result<()> {
        let passkeys = self.passkeys.as_ref().context("passkeys are unavailable")?;
        let id = {
            let ceremonies = self.ceremonies.lock().await;
            ceremonies
                .get(token)
                .filter(|entry| entry.owner == subject && entry.expires > Utc::now())
                .context("passkey ceremony not found or expired")?
                .session
                .clone()
        };
        let mut session = self.owned(subject, &id).await?;
        if let Some(minutes) = minutes {
            let seconds = session.requested_ttl.as_secs();
            let valid = session.approval()
                && seconds.is_multiple_of(60)
                && minutes == (seconds / 60) as i64;
            ensure!(valid, "invalid REST approval duration");
        }
        let ceremony = self
            .ceremonies
            .lock()
            .await
            .remove(token)
            .filter(|entry| entry.expires > Utc::now())
            .context("passkey ceremony not found or expired")?;
        match ceremony.state {
            CeremonyState::Authentication(state) => {
                ensure!(
                    session.public.state == State::AwaitingPasskey
                        && session.expires_at() > Utc::now(),
                    "emergency session is unavailable"
                );
                passkeys.finish_authentication(&state, response)?;
                ensure!(
                    ceremony.expires > Utc::now(),
                    "passkey ceremony expired during verification"
                );
                session.publish(&self.journal, true, false)?;
            }
            CeremonyState::Registration(state) => {
                ensure!(
                    session.active() && session.public.authentication == "totp",
                    "passkey enrollment proof is no longer active"
                );
                passkeys.finish_registration(state, response, &ceremony.label)?;
            }
        }
        Ok(())
    }

    pub async fn reload(&self, definitions: BTreeMap<String, Profile>, allowlist: &[AllowEntry]) {
        let entries: Vec<_> = self
            .sessions
            .lock()
            .await
            .values()
            .map(|entry| entry.session.clone())
            .collect();
        for entry in entries {
            let mut session = entry.lock().await;
            if !matches!(
                session.public.state,
                State::Revoked | State::Expired | State::Invalidated | State::RevocationPending
            ) && (!allowed(allowlist, &session.owner, &session.public.profile)
                || definitions.get(&session.public.profile) != Some(&session.definition))
            {
                session.public.state = State::Invalidated;
                session.access_token = None;
                session.device = None;
                session.invalidation_pending = session
                    .record(&self.journal, State::Invalidated, "session.invalidated")
                    .is_err();
                if session.invalidation_pending {
                    tracing::error!("could not record emergency session invalidation");
                }
            }
        }
        *self.profiles.write().expect("emergency profile lock") = definitions;
    }

    pub async fn pending(&self) -> Vec<(String, String)> {
        self.sessions
            .lock()
            .await
            .iter()
            .filter_map(|(id, entry)| {
                let session = entry.session.try_lock().ok()?;
                (session.public.state == State::RevocationPending)
                    .then(|| (entry.owner.clone(), id.clone()))
            })
            .collect()
    }

    pub async fn prune(&self) -> Result<()> {
        let mut registry = self.sessions.lock().await;
        let mut error = None;
        registry.retain(|_, entry| {
            let Ok(mut session) = entry.session.try_lock() else {
                return true;
            };
            if session.invalidation_pending {
                if let Err(err) =
                    session.record(&self.journal, State::Invalidated, "session.invalidated")
                {
                    error = Some(err);
                    return true;
                }
                session.invalidation_pending = false;
            }
            if session.public.state == State::RevocationPending
                || (session.expires_at() > Utc::now()
                    && !matches!(session.public.state, State::Revoked | State::Invalidated))
            {
                return true;
            }
            if !matches!(
                session.public.state,
                State::Revoked | State::Expired | State::Invalidated
            ) {
                if let Err(err) = session.record(&self.journal, State::Expired, "session.expired") {
                    error = Some(err);
                    return true;
                }
                session.public.state = State::Expired;
            }
            false
        });
        error.map_or(Ok(()), Err)
    }
}

fn allowed(allowlist: &[AllowEntry], subject: &str, name: &str) -> bool {
    allowlist.iter().any(|entry| {
        entry.subject == subject
            && entry
                .emergency_profiles
                .iter()
                .any(|profile| profile == name)
    })
}

pub fn random_id(size: usize) -> Result<String> {
    let mut data = vec![0; size];
    SystemRandom::new()
        .fill(&mut data)
        .map_err(|_| anyhow::anyhow!("generate emergency ID"))?;
    Ok(URL_SAFE_NO_PAD.encode(data))
}

fn decode_totp_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let canonical = Zeroizing::new(secret.trim().replace(' ', "").to_ascii_uppercase());
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(canonical.as_bytes())
            .context("invalid TOTP secret")?,
    );
    ensure!(key.len() >= 16, "invalid TOTP secret");
    Ok(key)
}

fn verify_totp(journal: &Journal, secret: &str, code: &str, now: i64) -> Result<()> {
    let secret = decode_totp_secret(secret)?;
    let canonical = Zeroizing::new(BASE32_NOPAD.encode(&secret));
    let identity = HEXLOWER.encode(&Sha256::digest(canonical.as_bytes()));
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
    let accepted = journal.write(|tx| check_code(tx, &identity, &key, code, now))?;
    ensure!(accepted, "invalid or already used TOTP code");
    Ok(())
}

fn check_code(
    tx: &Transaction<'_>,
    identity: &str,
    key: &hmac::Key,
    code: &str,
    now: i64,
) -> Result<bool> {
    let cutoff = now - 86400;
    let (failure_started, failures): (i64, i64) = tx
        .query_row(
            "SELECT started,failures FROM emergency_totp_failures WHERE identity=?1",
            [identity],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .filter(|(started, _)| *started > cutoff)
        .unwrap_or((now, 0));
    ensure!(failures < 10, "TOTP authentication failure limit reached");
    let (mut started, mut attempts, mut last): (i64, i64, i64) = tx
        .query_row(
            "SELECT started,attempts,last_step FROM emergency_totp WHERE identity=?1",
            [identity],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .unwrap_or((now, 0, -1));
    if now - started >= 30 {
        started = now;
        attempts = 0;
    }
    ensure!(
        attempts < 5,
        "TOTP authentication is temporarily rate limited"
    );
    let current = now / 30;
    let step = (current - 1..=current + 1).find(|step| {
        let expected = totp_value(key, *step);
        bool::from(expected.as_bytes().ct_eq(code.as_bytes()))
    });
    let accepted = step.is_some_and(|step| step > last);
    if let Some(step) = step.filter(|_| accepted) {
        last = step;
    } else {
        tx.execute("INSERT INTO emergency_totp_failures(identity,started,failures) VALUES (?1,?2,?3)
            ON CONFLICT(identity) DO UPDATE SET started=excluded.started,failures=excluded.failures",
            params![identity, failure_started, failures + 1])?;
    }
    tx.execute("INSERT INTO emergency_totp(identity,started,attempts,last_step) VALUES (?1,?2,?3,?4)
        ON CONFLICT(identity) DO UPDATE SET started=excluded.started,attempts=excluded.attempts,last_step=excluded.last_step",
        params![identity, started, attempts+1, last])?;
    tx.execute(
        "DELETE FROM emergency_totp WHERE started < ?1 AND last_step < ?2",
        params![cutoff, current - 3],
    )?;
    tx.execute(
        "DELETE FROM emergency_totp_failures WHERE started <= ?1",
        [cutoff],
    )?;
    Ok(accepted)
}

fn totp_value(key: &hmac::Key, step: i64) -> String {
    let tag = hmac::sign(key, &step.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes[bytes.len() - 1] & 15);
    let number = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fffffff;
    format!("{:06}", number % 1_000_000)
}

#[cfg(test)]
pub fn test_totp_code(secret: &str) -> Result<String> {
    Ok(totp_value(
        &hmac::Key::new(
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            &decode_totp_secret(secret)?,
        ),
        Utc::now().timestamp() / 30,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_watermark_and_attempt_budget_survive_restart() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("emergency.db");
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let journal = Journal::open(&path)?;
        verify_totp(&journal, secret, "287082", 59)?;
        drop(journal);
        let journal = Journal::open(&path)?;
        for _ in 0..4 {
            let error = verify_totp(&journal, secret, "287082", 59).unwrap_err();
            assert_eq!(error.to_string(), "invalid or already used TOTP code");
        }
        let error = verify_totp(&journal, secret, "287082", 59).unwrap_err();
        assert_eq!(
            error.to_string(),
            "TOTP authentication is temporarily rate limited"
        );
        Ok(())
    }
    #[tokio::test]
    async fn go_passkey_activates_caller_bound_approval_and_only_one_redeem_commits() -> Result<()>
    {
        use crate::passkeys::fixture;
        use serde_json::json;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("passkeys.json");
        let credential = fixture::existing(&path, 6)?;
        let passkeys = Passkeys::open(&fixture::config(&path)?)?;
        let db = dir.path().join("journal.db");
        let journal = Journal::open(&db)?;
        let profile: Profile =
            serde_json::from_value(json!({"provider":"approval","authentication":"webauthn",
            "passkey_credentials":[credential]}))?;
        profile.validate()?;
        let allow: AllowEntry =
            serde_json::from_value(json!({"subject":"owner","emergency_profiles":["release"]}))?;
        let service = Emergency::new(
            BTreeMap::from([("release".into(), profile)]),
            journal.clone(),
            Some(passkeys),
        )?;
        let digest = "ab".repeat(32);
        let issued = service
            .create(
                &[allow],
                "owner".into(),
                CreateSession {
                    profile: "release".into(),
                    ttl_seconds: Some(300),
                    scopes: vec![],
                    approval_digest: digest.clone(),
                    approval_label: "Approve fixture release".into(),
                },
            )
            .await?;
        let token = issued
            .verification_uri
            .as_ref()
            .unwrap()
            .split_once('#')
            .unwrap()
            .1;
        assert!(service.ceremony_options("other", token).await.is_err());
        let options = service.ceremony_options("owner", token).await?;
        assert_eq!(options["approval_label"], "Approve fixture release");
        let challenge = options["public_key"]["publicKey"]["challenge"]
            .as_str()
            .unwrap();
        let response = fixture::assertion(challenge, 7)?;
        service
            .verify_passkey("owner", token, &response, Some(5))
            .await?;
        assert!(
            service
                .verify_passkey("owner", token, &response, Some(5))
                .await
                .is_err()
        );
        let redeem = || async {
            let mut session = service.owned("owner", &issued.id).await?;
            assert_eq!(session.expires_at(), issued.expires_at);
            session.redeem(&journal, &digest)
        };
        let (first, second) = tokio::join!(redeem(), redeem());
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let conn = rusqlite::Connection::open(&db)?;
        let recorded: i64 = conn.query_row(
            "SELECT redeemed FROM emergency_approvals WHERE session_id=?1",
            [&issued.id],
            |row| row.get(0),
        )?;
        assert_eq!(recorded, 1);
        assert_eq!(
            crate::operations::read_passkeys(&path)?["credentials"][0]["authenticator"]["signCount"],
            7
        );
        Ok(())
    }
}
