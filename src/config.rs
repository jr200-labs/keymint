use anyhow::{Context, Result, ensure};
use reqwest::Url;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keys: BTreeMap<String, Key>,
    #[serde(default)]
    pub release_keys: BTreeMap<String, crate::release::Key>,
    #[serde(default)]
    pub telegram_relays: BTreeMap<String, crate::telegram_relay::Relay>,
    #[serde(default)]
    pub allowlist: Vec<AllowEntry>,
    #[serde(default)]
    pub expected_audiences: Vec<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    #[serde(default, rename = "emergency_profiles")]
    _emergency_profiles: serde_yaml::Value,
    #[serde(default, rename = "passkeys")]
    _passkeys: serde_yaml::Value,
    #[serde(default)]
    pub emergency_state_file: PathBuf,
    #[serde(default)]
    emergency_journal_retention: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub subject: String,
    #[serde(default)]
    pub keys: Vec<String>,
    pub repositories: Option<Vec<String>>,
    pub permissions: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub require_scope: bool,
    #[serde(default)]
    pub emergency_profiles: Vec<String>,
    #[serde(default)]
    pub release_keys: Vec<String>,
}

impl AllowEntry {
    pub fn allows_scope(&self, scope: &crate::mint::Scope) -> bool {
        if self.require_scope && (scope.repositories.is_empty() || scope.permissions.is_empty()) {
            return false;
        }
        let repositories_allowed = self.repositories.as_ref().is_none_or(|repositories| {
            !scope.repositories.is_empty()
                && scope.repositories.iter().all(|requested| {
                    repositories
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(requested))
                })
        });
        let permissions_allowed = self.permissions.as_ref().is_none_or(|permissions| {
            !scope.permissions.is_empty()
                && scope.permissions.iter().all(|(name, requested)| {
                    permissions.get(name).is_some_and(|ceiling| {
                        ceiling == requested || (ceiling == "write" && requested == "read")
                    })
                })
        });
        repositories_allowed && permissions_allowed
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub app_id: i64,
    pub install_id: i64,
    #[serde(default)]
    pub private_key_file: PathBuf,
    #[serde(default)]
    pub private_key_sops: PathBuf,
    #[serde(default)]
    pub github_owner: String,
    #[serde(default)]
    pub api_base_url: String,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let default_path;
        let path = match path.filter(|path| !path.as_os_str().is_empty()) {
            Some(path) => path,
            None => {
                default_path = config_dir()?.join("keymint/config.yaml");
                &default_path
            }
        };
        let contents =
            std::fs::read(path).with_context(|| format!("config: read {}", path.display()))?;
        Self::parse(&contents).with_context(|| format!("config: load {}", path.display()))
    }

    pub fn parse(contents: &[u8]) -> Result<Self> {
        let config: Self = serde_yaml::from_slice(contents).context("config: parse")?;
        config.validate().context("config: validate")?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.keys.is_empty(), "no keys defined");
        for (name, key) in &self.keys {
            ensure!(!name.is_empty(), "key name must be non-empty");
            ensure!(key.app_id != 0, "key {name:?}: app_id is required");
            ensure!(key.install_id != 0, "key {name:?}: install_id is required");
            ensure!(
                !key.private_key_file.as_os_str().is_empty()
                    || !key.private_key_sops.as_os_str().is_empty(),
                "key {name:?}: must set private_key_file or private_key_sops"
            );
            key.api_base().with_context(|| format!("key {name:?}"))?;
        }
        self.journal_retention()?;
        let mut bindings = BTreeMap::new();
        for (index, entry) in self.allowlist.iter().enumerate() {
            ensure!(
                !entry.subject.is_empty(),
                "allowlist[{index}]: subject is required"
            );
            ensure!(
                !(entry.keys.is_empty()
                    && entry.emergency_profiles.is_empty()
                    && entry.release_keys.is_empty()),
                "allowlist[{index}]: keys, emergency_profiles, or release_keys is required"
            );
            let restricted =
                entry.require_scope || entry.repositories.is_some() || entry.permissions.is_some();
            if restricted {
                ensure!(
                    !entry.keys.is_empty()
                        && entry
                            .repositories
                            .as_ref()
                            .is_none_or(|repos| !repos.is_empty())
                        && entry
                            .permissions
                            .as_ref()
                            .is_none_or(|perms| !perms.is_empty()),
                    "allowlist[{index}]: token ceilings require keys and nonempty configured scopes"
                );
                crate::mint::Scope {
                    repositories: entry.repositories.clone().unwrap_or_default(),
                    permissions: entry.permissions.clone().unwrap_or_default(),
                }
                .validate()
                .with_context(|| format!("allowlist[{index}]"))?;
            }
            for key in &entry.keys {
                ensure!(
                    self.keys.contains_key(key),
                    "allowlist[{index}]: unknown key {key:?} (not in keys map)"
                );
                if let Some(previous_restricted) =
                    bindings.insert((&entry.subject, key), restricted)
                {
                    ensure!(
                        !(previous_restricted || restricted),
                        "allowlist[{index}]: overlapping token policies for subject {:?} and key {key:?}",
                        entry.subject
                    );
                }
            }
            for name in &entry.emergency_profiles {
                ensure!(
                    self._emergency_profiles.get(name).is_some(),
                    "allowlist[{index}]: unknown emergency profile {name:?}"
                );
            }
            for name in &entry.release_keys {
                ensure!(
                    self.release_keys.contains_key(name),
                    "allowlist[{index}]: unknown release key {name:?}"
                );
            }
        }
        let mut destinations = std::collections::BTreeSet::new();
        for (name, key) in &self.release_keys {
            key.validate(name)
                .with_context(|| format!("release key {name:?}"))?;
            ensure!(
                self.keys.contains_key(&key.github_key),
                "release key {name:?}: github_key must reference a configured installation key"
            );
            for repo in &key.repositories {
                for scope in key.scopes() {
                    ensure!(
                        destinations.insert((repo, scope)),
                        "release key {name:?}: overlapping repository and secret scope"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn validate_service(&self) -> Result<()> {
        ensure!(
            !self.expected_audiences.is_empty()
                && self
                    .expected_audiences
                    .iter()
                    .all(|value| !value.trim().is_empty()),
            "expected_audiences must contain nonempty audiences"
        );
        for (name, key) in &self.release_keys {
            key.validate_file()
                .with_context(|| format!("release key {name:?}"))?;
        }
        let profiles = self.runtime_profiles()?;
        let passkeys = self.runtime_passkeys()?;
        let mut urls = std::collections::BTreeSet::new();
        let mut subjects = std::collections::BTreeSet::new();
        for (name, relay) in &self.telegram_relays {
            let url = relay
                .validate(name)
                .with_context(|| format!("telegram relay {name:?}"))?;
            ensure!(
                urls.insert(url) && subjects.insert(&relay.relay_subject),
                "each Telegram relay requires its own HTTPS origin and workload identity"
            );
            ensure!(
                !self.emergency_state_file.as_os_str().is_empty() && passkeys.is_some(),
                "Telegram enrollment requires durable passkey approvals"
            );
            ensure!(
                profiles
                    .get(&relay.approval_profile)
                    .is_some_and(|profile| profile.is_approval())
                    && self
                        .allowlist
                        .iter()
                        .any(|entry| entry.subject == relay.operator_subject
                            && entry.emergency_profiles.contains(&relay.approval_profile)),
                "Telegram operator must be allowed to use its configured approval profile"
            );
            relay
                .validate_files()
                .with_context(|| format!("telegram relay {name:?}"))?;
        }
        for (name, profile) in &profiles {
            ensure!(
                !profile.uses_passkeys() || passkeys.is_some(),
                "emergency profile {name:?} requires passkeys configuration"
            );
        }
        if let Some(passkeys) = passkeys {
            passkeys.check_scopes(
                profiles
                    .values()
                    .filter_map(|profile| profile.passkey_credentials.as_ref())
                    .flatten()
                    .map(String::as_str),
            )?;
        }
        for (name, key) in &self.keys {
            ensure!(
                !key.private_key_file.as_os_str().is_empty(),
                "service key {name:?} requires private_key_file"
            );
            let pem = zeroize::Zeroizing::new(
                std::fs::read(&key.private_key_file)
                    .with_context(|| format!("key {name:?}: read private_key_file"))?,
            );
            jsonwebtoken::EncodingKey::from_rsa_pem(&pem).with_context(|| {
                format!("key {name:?}: private_key_file must contain an RSA private key")
            })?;
        }
        Ok(())
    }

    pub fn runtime_passkeys(&self) -> Result<Option<crate::passkeys::Config>> {
        if self._passkeys.is_null() {
            return Ok(None);
        }
        let config: crate::passkeys::Config = serde_yaml::from_value(self._passkeys.clone())
            .context("parse passkeys configuration")?;
        config.validate()?;
        Ok(Some(config))
    }

    pub fn runtime_profiles(&self) -> Result<BTreeMap<String, crate::emergency::Profile>> {
        if self._emergency_profiles.is_null() {
            return Ok(BTreeMap::new());
        }
        let profiles: BTreeMap<String, crate::emergency::Profile> =
            serde_yaml::from_value(self._emergency_profiles.clone())
                .context("parse emergency profiles")?;
        ensure!(
            profiles.is_empty() || !self.emergency_state_file.as_os_str().is_empty(),
            "emergency_state_file is required for recoverable credential revocation"
        );
        for (name, profile) in &profiles {
            profile
                .validate()
                .with_context(|| format!("emergency profile {name:?}"))?;
        }
        Ok(profiles)
    }

    pub fn journal_retention(&self) -> Result<Option<std::time::Duration>> {
        if self.emergency_journal_retention.is_empty() {
            return Ok(None);
        }
        let retention = humantime::parse_duration(&self.emergency_journal_retention)?;
        ensure!(
            !self.emergency_state_file.as_os_str().is_empty()
                && retention >= std::time::Duration::from_secs(24 * 60 * 60),
            "emergency_journal_retention requires emergency_state_file and a duration of at least 24h"
        );
        Ok(Some(retention))
    }

    pub fn validate_reload_from(&self, current: &Self) -> Result<()> {
        ensure!(
            self._passkeys == current._passkeys
                && self.emergency_state_file == current.emergency_state_file
                && self.expected_audiences == current.expected_audiences,
            "passkeys, emergency_state_file and expected_audiences changes require restart"
        );
        Ok(())
    }

    pub fn key_for_https_remote(&self, host: &str, path: &str) -> Option<&Key> {
        let remote =
            Url::parse(&format!("https://{host}/{}", path.trim_start_matches('/'))).ok()?;
        let mut segments = remote.path_segments()?;
        let owner = segments.next()?;
        segments
            .next()
            .filter(|repository| !repository.is_empty())?;
        self.keys.values().find(|key| {
            if !key.github_owner.eq_ignore_ascii_case(owner) {
                return false;
            }
            if key.api_base_url.is_empty() {
                return remote.host_str() == Some("github.com") && remote.port().is_none();
            }
            key.api_base()
                .is_ok_and(|api| remote.host_str() == api.host_str() && remote.port() == api.port())
        })
    }
}

impl Key {
    pub fn api_base(&self) -> Result<Url> {
        validated_api_base(&self.api_base_url)
    }
}

pub fn validated_api_base(raw: &str) -> Result<Url> {
    let value = if raw.is_empty() {
        "https://api.github.com"
    } else {
        raw
    };
    let url = Url::parse(value).context("invalid api_base_url")?;
    ensure!(
        value.starts_with("https://")
            && url.host_str().is_some()
            && !value["https://".len()..]
                .split('/')
                .next()
                .unwrap_or_default()
                .contains('@')
            && url.query().is_none()
            && url.fragment().is_none(),
        "api_base_url must be an absolute HTTPS API URL without credentials, query, or fragment"
    );
    Ok(url)
}

fn config_dir() -> Result<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    if let Some(dir) = env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        return Ok(dir.into());
    }

    let home = env::var_os("HOME")
        .filter(|dir| !dir.is_empty())
        .context("config: determine user config dir")?;
    #[cfg(target_os = "macos")]
    const USER_CONFIG: &str = "Library/Application Support";
    #[cfg(not(target_os = "macos"))]
    const USER_CONFIG: &str = ".config";

    Ok(PathBuf::from(home).join(USER_CONFIG))
}
