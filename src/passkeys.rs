use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::Url;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use webauthn_rs_core::{
    WebauthnCore,
    proto::{
        AttestationFormat, AuthenticationState, COSEAlgorithm, COSEKey, COSEKeyType, COSEOKPKey,
        CollectedClientData, Credential, EDDSACurve, PublicKeyCredential,
        RegisterPublicKeyCredential, RegistrationState, UserVerificationPolicy,
    },
};

use crate::operations::{credential_id, read_passkeys, write_passkeys};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    rp_id: String,
    rp_display_name: String,
    rp_origins: Vec<Url>,
    verification_url: Url,
    state_file: PathBuf,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.rp_id.is_empty()
                && !self.rp_display_name.is_empty()
                && !self.rp_origins.is_empty()
                && !self.state_file.as_os_str().is_empty(),
            "passkeys: relying party, origins, verification URL and state file are required"
        );
        let plain_https = |url: &Url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.query().is_none()
        };
        ensure!(
            plain_https(&self.verification_url),
            "invalid passkey verification URL"
        );
        for url in &self.rp_origins {
            let host = url.host_str().unwrap_or_default();
            ensure!(
                plain_https(url)
                    && url.path() == "/"
                    && (host == self.rp_id
                        || host
                            .strip_suffix(&self.rp_id)
                            .is_some_and(|prefix| prefix.ends_with('.'))),
                "passkey origins must be HTTPS origins within the relying party ID"
            );
        }
        Ok(())
    }

    pub fn check_scopes<'a>(&self, allowed: impl Iterator<Item = &'a str>) -> Result<()> {
        let user = match read_passkeys(&self.state_file) {
            Ok(user) => user,
            Err(error) if is_missing(&error) => Value::Null,
            Err(error) => return Err(error),
        };
        let mut eligible = std::collections::BTreeSet::new();
        for entry in user["credentials"].as_array().into_iter().flatten() {
            if !flagged(entry) {
                let _ = read_credential(entry)?;
                eligible.insert(credential_id(entry)?);
            }
        }
        for id in allowed {
            ensure!(
                eligible.contains(id),
                "passkey credential {id} is missing or flagged"
            );
        }
        Ok(())
    }
}

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

pub struct Passkeys {
    core: WebauthnCore,
    path: PathBuf,
    user: Mutex<Value>,
    verification_url: String,
    rp_hash: [u8; 32],
}

pub enum CeremonyState {
    Authentication(Box<AssertionState>),
    Registration(RegistrationState),
}

pub struct AssertionState {
    core: AuthenticationState,
    challenge: Vec<u8>,
    ed25519: BTreeMap<Vec<u8>, ([u8; 32], bool)>,
}

impl Passkeys {
    pub fn open(config: &Config) -> Result<Self> {
        config.validate()?;
        let user = match read_passkeys(&config.state_file) {
            Ok(user) => user,
            Err(error) if is_missing(&error) => {
                let mut user_id = [0u8; 32];
                SystemRandom::new()
                    .fill(&mut user_id)
                    .map_err(|_| anyhow::anyhow!("generate passkey user ID"))?;
                create_directory(config.state_file.parent())?;
                let user = json!({"id":STANDARD.encode(user_id),"name":"operator",
                    "display_name":"Emergency operator","credentials":[]});
                write_passkeys(&config.state_file, &user)?;
                user
            }
            Err(error) => return Err(error),
        };
        // The existing Go file uses a 32-byte user handle. The core builder accepts
        // the existing opaque handle and explicitly requires user verification.
        let core = WebauthnCore::new_unsafe_experts_only(
            &config.rp_display_name,
            &config.rp_id,
            config.rp_origins.clone(),
            Duration::from_secs(300),
            Some(false),
            Some(false),
        );
        Ok(Self {
            core,
            rp_hash: ring::digest::digest(&ring::digest::SHA256, config.rp_id.as_bytes())
                .as_ref()
                .try_into()
                .unwrap(),
            path: config.state_file.clone(),
            user: Mutex::new(user),
            verification_url: config
                .verification_url
                .as_str()
                .trim_end_matches('/')
                .into(),
        })
    }

    pub fn ceremony_url(&self, token: &str) -> String {
        format!("{}/#{token}", self.verification_url)
    }

    pub fn begin_authentication(
        &self,
        allowed: Option<&[String]>,
    ) -> Result<(Value, CeremonyState)> {
        let user = self.user.lock().expect("passkey state lock");
        let mut credentials = Vec::new();
        for entry in user["credentials"].as_array().into_iter().flatten() {
            if !flagged(entry)
                && allowed.is_none_or(|ids| credential_id(entry).is_ok_and(|id| ids.contains(&id)))
            {
                credentials.push(read_credential(entry)?);
            }
        }
        ensure!(!credentials.is_empty(), "no passkeys are enrolled");
        let ed25519 = credentials
            .iter()
            .filter_map(|entry| match &entry.cred.key {
                COSEKeyType::EC_OKP(key) => Some((
                    entry.cred_id.clone(),
                    (key.x.as_slice().try_into().ok()?, entry.backup_eligible),
                )),
                _ => None,
            })
            .collect();
        let builder = self.core.new_challenge_authenticate_builder(
            credentials,
            Some(UserVerificationPolicy::Required),
        )?;
        let (options, state) = self.core.generate_challenge_authenticate(builder)?;
        let state = AssertionState {
            core: state,
            challenge: options.public_key.challenge.clone(),
            ed25519,
        };
        Ok((
            serde_json::to_value(options)?,
            CeremonyState::Authentication(Box::new(state)),
        ))
    }

    pub fn begin_registration(&self) -> Result<(Value, CeremonyState)> {
        let user = self.user.lock().expect("passkey state lock");
        let user_id = decode_field(&user, "id")?;
        let excluded = user["credentials"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|entry| decode_field(entry, "id"))
            .collect::<Result<Vec<_>>>()?;
        let builder = self
            .core
            .new_challenge_register_builder(
                &user_id,
                user["name"].as_str().context("missing passkey user name")?,
                user["display_name"]
                    .as_str()
                    .context("missing passkey display name")?,
            )?
            .require_resident_key(true)
            .user_verification_policy(UserVerificationPolicy::Required)
            .exclude_credentials(Some(excluded));
        let (options, state) = self.core.generate_challenge_register(builder)?;
        Ok((
            serde_json::to_value(options)?,
            CeremonyState::Registration(state),
        ))
    }

    pub fn finish_authentication(&self, state: &AssertionState, response: &[u8]) -> Result<()> {
        let mut user = self.user.lock().expect("passkey state lock");
        let response: PublicKeyCredential = serde_json::from_slice(response)?;
        let registered_user = decode_field(&user, "id")?;
        if let Some(handle) = &response.response.user_handle {
            ensure!(
                handle.as_slice() == registered_user.as_slice(),
                "assertion belongs to another user"
            );
        }
        ensure!(
            response.type_ == "public-key"
                && URL_SAFE_NO_PAD.decode(&response.id)? == response.raw_id,
            "invalid WebAuthn credential ID"
        );
        let (current, backup_eligible, backup_state) =
            if let Some((key, backup)) = state.ed25519.get(&response.raw_id) {
                self.verify_legacy_ed25519(&response, &state.challenge, key, *backup)?
            } else {
                let result = self.core.authenticate_credential(&response, &state.core)?;
                ensure!(
                    result.user_verified(),
                    "passkey user verification is required"
                );
                (
                    u64::from(result.counter()),
                    result.backup_eligible(),
                    result.backup_state(),
                )
            };
        let encoded = STANDARD.encode(&response.raw_id);
        let mut updated = user.clone();
        let entry = updated["credentials"]
            .as_array_mut()
            .and_then(|entries| {
                entries
                    .iter_mut()
                    .find(|entry| entry["id"].as_str() == Some(encoded.as_str()))
            })
            .context("verified passkey is not enrolled")?;
        ensure!(!flagged(entry), "passkey is blocked");
        let previous = entry["authenticator"]["signCount"]
            .as_u64()
            .unwrap_or_default();
        if (previous != 0 || current != 0) && current <= previous {
            entry["authenticator"]["cloneWarning"] = Value::Bool(true);
            // Block immediately, including when the store write fails.
            *user = updated;
            write_passkeys(&self.path, &user)?;
            anyhow::bail!("passkey signature counter did not advance");
        }
        entry["authenticator"]["signCount"] = json!(current);
        entry["flags"]["backupEligible"] = json!(backup_eligible);
        entry["flags"]["backupState"] = json!(backup_state);
        write_passkeys(&self.path, &updated)?;
        *user = updated;
        Ok(())
    }

    // The upstream WebAuthn crate currently rejects Ed25519 COSE keys.
    // Accept assertions from already enrolled Ed25519 passkeys with the same
    // challenge, origin, RP, presence, verification, and counter requirements.
    fn verify_legacy_ed25519(
        &self,
        response: &PublicKeyCredential,
        challenge: &[u8],
        key: &[u8; 32],
        expected_backup: bool,
    ) -> Result<(u64, bool, bool)> {
        let assertion = &response.response;
        let client: CollectedClientData = serde_json::from_slice(&assertion.client_data_json)?;
        ensure!(
            client.type_ == "webauthn.get"
                && client.challenge == challenge
                && client.cross_origin != Some(true)
                && self.core.get_allowed_origins().contains(&client.origin),
            "invalid WebAuthn client data"
        );
        let auth = &assertion.authenticator_data;
        // The server requests no authenticator extensions for this ceremony.
        ensure!(
            auth.len() == 37 && auth[..32] == self.rp_hash && auth[32] & 0xc5 == 0x05,
            "invalid WebAuthn authenticator data"
        );
        let flags = auth[32];
        let eligible = flags & 0x08 != 0;
        let backed_up = flags & 0x10 != 0;
        ensure!(
            eligible == expected_backup && (!backed_up || eligible),
            "invalid WebAuthn backup flags"
        );
        let client_hash = ring::digest::digest(&ring::digest::SHA256, &assertion.client_data_json);
        let mut signed = auth.clone();
        signed.extend_from_slice(client_hash.as_ref());
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(&signed, &assertion.signature)
            .map_err(|_| anyhow::anyhow!("invalid WebAuthn assertion signature"))?;
        Ok((
            u64::from(u32::from_be_bytes(auth[33..37].try_into().unwrap())),
            eligible,
            backed_up,
        ))
    }

    pub fn finish_registration(
        &self,
        state: RegistrationState,
        response: &[u8],
        label: &str,
    ) -> Result<()> {
        let response: RegisterPublicKeyCredential = serde_json::from_slice(response)?;
        let credential = self.core.register_credential(&response, &state, None)?;
        ensure!(
            credential.user_verified,
            "passkey user verification is required"
        );
        let mut user = self.user.lock().expect("passkey state lock");
        let mut updated = user.clone();
        if updated["credentials"].is_null() {
            updated["credentials"] = json!([]);
        }
        let enrolled = updated["credentials"]
            .as_array_mut()
            .context("invalid passkey inventory")?;
        let id = STANDARD.encode(&credential.cred_id);
        ensure!(
            !enrolled
                .iter()
                .any(|entry| entry["id"].as_str() == Some(&id)),
            "passkey credential is already enrolled"
        );
        let entry = json!({
            "id":id,
            "publicKey": STANDARD.encode(write_cose(&credential.cred)?),
            "attestationType":"none",
            "transport":credential.transports,
            "flags":{"userPresent":true,"userVerified":credential.user_verified,
                "backupEligible":credential.backup_eligible,"backupState":credential.backup_state},
            "authenticator":{"signCount":credential.counter},
        });
        if !label.is_empty() {
            let inventory_id = credential_id(&entry)?;
            enrolled.push(entry);
            updated["credential_labels"][inventory_id] = json!(label);
        } else {
            enrolled.push(entry);
        }
        write_passkeys(&self.path, &updated)?;
        *user = updated;
        Ok(())
    }
}

fn create_directory(directory: Option<&Path>) -> Result<()> {
    if let Some(path) = directory.filter(|path| !path.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    Ok(())
}

fn flagged(entry: &Value) -> bool {
    entry["authenticator"]["cloneWarning"]
        .as_bool()
        .unwrap_or(false)
}

fn decode_field(entry: &Value, key: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(entry[key].as_str().context("missing passkey field")?)?)
}

fn read_credential(entry: &Value) -> Result<Credential> {
    let encoded = decode_field(entry, "publicKey")?;
    let cose = serde_cbor_2::from_slice::<Cbor>(&encoded)?;
    let cred = match &cose {
        Cbor::Map(fields) if fields.get(&Cbor::Integer(1)) == Some(&Cbor::Integer(1)) => {
            ensure!(
                matches!(fields.get(&Cbor::Integer(3)), Some(Cbor::Integer(-8 | -19)))
                    && fields.get(&Cbor::Integer(-1)) == Some(&Cbor::Integer(6)),
                "unsupported EdDSA passkey"
            );
            let Some(Cbor::Bytes(key)) = fields.get(&Cbor::Integer(-2)) else {
                anyhow::bail!("missing Ed25519 passkey");
            };
            ensure!(key.len() == 32, "invalid Ed25519 passkey");
            COSEKey {
                type_: COSEAlgorithm::EDDSA,
                key: COSEKeyType::EC_OKP(COSEOKPKey {
                    curve: EDDSACurve::ED25519,
                    x: key.clone(),
                }),
            }
        }
        _ => COSEKey::try_from(&cose)?,
    };
    let boolean = |flag| entry["flags"][flag].as_bool().unwrap_or(false);
    Ok(Credential {
        cred_id: decode_field(entry, "id")?,
        cred,
        // Compare the authenticated counter against the current file record under
        // the same lock used to persist clone warnings. A challenge is a snapshot.
        counter: 0,
        transports: entry
            .get("transport")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .flatten(),
        user_verified: boolean("userVerified"),
        backup_eligible: boolean("backupEligible"),
        backup_state: boolean("backupState"),
        registration_policy: UserVerificationPolicy::Required,
        extensions: Default::default(),
        attestation: Default::default(),
        attestation_format: AttestationFormat::None,
    })
}

fn write_cose(key: &COSEKey) -> Result<Vec<u8>> {
    let (typ, first, second, third) = match &key.key {
        COSEKeyType::EC_OKP(key) => (
            1,
            Cbor::Integer(key.curve.clone() as i128),
            Cbor::Bytes(key.x.clone()),
            None,
        ),
        COSEKeyType::EC_EC2(key) => (
            2,
            Cbor::Integer(key.curve.clone() as i128),
            Cbor::Bytes(key.x.clone()),
            Some(Cbor::Bytes(key.y.clone())),
        ),
        COSEKeyType::RSA(key) => (
            3,
            Cbor::Bytes(key.n.clone()),
            Cbor::Bytes(key.e.to_vec()),
            None,
        ),
    };
    let mut fields = BTreeMap::from([
        (Cbor::Integer(1), Cbor::Integer(typ)),
        (Cbor::Integer(3), Cbor::Integer(key.type_ as i128)),
        (Cbor::Integer(-1), first),
        (Cbor::Integer(-2), second),
    ]);
    if let Some(third) = third {
        fields.insert(Cbor::Integer(-3), third);
    }
    Ok(serde_cbor_2::to_vec(&Cbor::Map(fields))?)
}

#[cfg(test)]
pub mod fixture {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    const ID: &[u8] = b"fixture-passkey";
    const HANDLE: &[u8] = b"fixture-existing-go-user-handle!";

    fn key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap()
    }

    pub fn existing(path: &Path, count: u32) -> Result<String> {
        let key = key();
        let cose = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(1)),
            (Cbor::Integer(3), Cbor::Integer(-8)),
            (Cbor::Integer(-1), Cbor::Integer(6)),
            (
                Cbor::Integer(-2),
                Cbor::Bytes(key.public_key().as_ref().to_vec()),
            ),
        ])))?;
        let entry = json!({"id":STANDARD.encode(ID),"publicKey":STANDARD.encode(cose),
            "attestationType":"none","flags":{"userPresent":true,"userVerified":true},
            "authenticator":{"signCount":count}});
        let inventory_id = credential_id(&entry)?;
        write_passkeys(
            path,
            &json!({"id":STANDARD.encode(HANDLE), "name":"operator",
            "display_name":"Emergency operator","credentials":[entry]}),
        )?;
        Ok(inventory_id)
    }

    pub fn config(path: &Path) -> Result<Config> {
        Ok(serde_json::from_value(json!({
            "rp_id":"passkeys.example.com", "rp_display_name":"Keymint",
            "rp_origins":["https://passkeys.example.com"],
            "verification_url":"https://passkeys.example.com/verify",
            "state_file":path,
        }))?)
    }

    pub fn assertion(challenge: &str, count: u32) -> Result<Vec<u8>> {
        let client = serde_json::to_vec(&json!({"type":"webauthn.get", "challenge":challenge,
            "origin":"https://passkeys.example.com", "crossOrigin":false}))?;
        let mut auth = Sha256::digest(b"passkeys.example.com").to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&count.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = key().sign(&signed);
        let id = URL_SAFE_NO_PAD.encode(ID);
        Ok(serde_json::to_vec(&json!({
            "id":id, "rawId":id, "type":"public-key",
            "response":{ "clientDataJSON":URL_SAFE_NO_PAD.encode(client),
                "authenticatorData":URL_SAFE_NO_PAD.encode(auth),
                "signature":URL_SAFE_NO_PAD.encode(signature.as_ref()),
                "userHandle":URL_SAFE_NO_PAD.encode(HANDLE) },
            "clientExtensionResults":{}
        }))?)
    }

    #[test]
    fn refuses_counter_rollback_and_persists_clone_warning_in_go_format() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("passkeys.json");
        let id = existing(&path, 7)?;
        let passkeys = Passkeys::open(&config(&path)?)?;
        let (options, CeremonyState::Authentication(state)) =
            passkeys.begin_authentication(Some(&[id]))?
        else {
            anyhow::bail!("expected assertion options");
        };
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .context("missing challenge")?;
        let error = passkeys
            .finish_authentication(&state, &assertion(challenge, 7)?)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "passkey signature counter did not advance"
        );
        let user = read_passkeys(&path)?;
        assert_eq!(
            user["credentials"][0]["authenticator"]["cloneWarning"],
            true
        );
        assert!(
            Passkeys::open(&config(&path)?)?
                .begin_authentication(None)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn registers_p256_in_go_format_and_authenticates() -> Result<()> {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("passkeys.json");
        let passkeys = Passkeys::open(&config(&path)?)?;
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public = key.public_key().as_ref();
        let cose = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(public[1..33].to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(public[33..65].to_vec())),
        ])))?;
        let (options, CeremonyState::Registration(state)) = passkeys.begin_registration()? else {
            anyhow::bail!("expected registration challenge");
        };
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .context("missing challenge")?;
        let client = serde_json::to_vec(&json!({"type":"webauthn.create", "challenge":challenge,
            "origin":"https://passkeys.example.com", "crossOrigin":false}))?;
        let mut data = passkeys.rp_hash.to_vec();
        data.push(0x45);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&(ID.len() as u16).to_be_bytes());
        data.extend_from_slice(ID);
        data.extend_from_slice(&cose);
        let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        ])))?;
        let id = URL_SAFE_NO_PAD.encode(ID);
        let response = serde_json::to_vec(&json!({
            "id":id,"rawId":id,"type":"public-key",
            "response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),
                "attestationObject":URL_SAFE_NO_PAD.encode(attestation)},
            "clientExtensionResults":{},
        }))?;
        passkeys.finish_registration(state, &response, "fixture P256")?;
        let user = read_passkeys(&path)?;
        let stored = &user["credentials"][0];
        assert_eq!(decode_field(stored, "id")?, ID);
        assert_eq!(decode_field(stored, "publicKey")?, cose);
        let (options, CeremonyState::Authentication(state)) =
            passkeys.begin_authentication(None)?
        else {
            anyhow::bail!("expected authentication challenge");
        };
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .context("missing challenge")?;
        let client = serde_json::to_vec(&json!({"type":"webauthn.get", "challenge":challenge,
            "origin":"https://passkeys.example.com", "crossOrigin":false}))?;
        let mut auth = passkeys.rp_hash.to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&1u32.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = key.sign(&rng, &signed).unwrap();
        let handle = decode_field(&user, "id")?;
        let response = serde_json::to_vec(&json!({
            "id":id,"rawId":id,"type":"public-key",
            "response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),
                "authenticatorData":URL_SAFE_NO_PAD.encode(auth),
                "signature":URL_SAFE_NO_PAD.encode(signature.as_ref()),
                "userHandle":URL_SAFE_NO_PAD.encode(handle)},
            "clientExtensionResults":{},
        }))?;
        passkeys.finish_authentication(&state, &response)?;
        assert_eq!(
            read_passkeys(&path)?["credentials"][0]["authenticator"]["signCount"],
            1
        );
        Ok(())
    }
}
