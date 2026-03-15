use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_core::secrecy::ExposeSecret;
use age_plugin::identity::{self, IdentityPluginV1};
use age_plugin::recipient::{self, RecipientPluginV1};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use kage_comm::ipc::KageStanza;
use kage_comm::kid::Kid;
use kage_comm::transport::default_daemon_transport;
use std::collections::HashMap;
use std::io;

fn age_stanza_from_wrapped(kid: &Kid, wrapped: &KageStanza) -> io::Result<Stanza> {
    let payload = BASE64
        .decode(wrapped.payload_b64.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Stanza {
        tag: "kage".into(),
        args: vec![BASE64.encode(kid.0), wrapped.nonce_b64.clone()],
        body: payload,
    })
}

fn wrapped_from_age_stanza(
    file_index: usize,
    stanza_index: usize,
    stanza: &Stanza,
) -> Result<KageStanza, identity::Error> {
    if stanza.args.len() != 2 {
        return Err(identity::Error::Stanza {
            file_index,
            stanza_index,
            message: "invalid stanza args".into(),
        });
    }
    let kid_b64 = &stanza.args[0];
    let nonce_b64 = &stanza.args[1];
    let payload_b64 = BASE64.encode(&stanza.body);
    KageStanza::from_age_parts(kid_b64, nonce_b64, &payload_b64).map_err(|e| {
        identity::Error::Stanza {
            file_index,
            stanza_index,
            message: e.to_string(),
        }
    })
}

#[derive(Debug, Parser)]
struct PluginOptions {
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

struct KageRecipientPlugin {
    recipients: Vec<Kid>,
}

impl RecipientPluginV1 for KageRecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        _plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if bytes.len() != 16 {
            return Err(recipient::Error::Recipient {
                index,
                message: "invalid KID length".into(),
            });
        }
        self.recipients
            .push(Kid(bytes.try_into().expect("len checked")));
        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        Err(recipient::Error::Identity {
            index,
            message: "encrypt-to-identity unsupported".into(),
        })
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl age_plugin::Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let transport = default_daemon_transport().map_err(|e| io::Error::other(e.to_string()))?;

        let mut out = Vec::with_capacity(file_keys.len());
        for file_key in file_keys {
            let mut stanzas = Vec::with_capacity(self.recipients.len());
            for kid in &self.recipients {
                let kid_bech32 = kid
                    .to_bech32()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let stanza = runtime
                    .block_on(transport.wrap_key(&kid_bech32, file_key.expose_secret()))
                    .map_err(|e| io::Error::other(e.to_string()))?;
                stanzas.push(age_stanza_from_wrapped(kid, &stanza)?);
            }
            out.push(stanzas);
        }

        Ok(Ok(out))
    }
}

struct KageIdentityPlugin;

impl IdentityPluginV1 for KageIdentityPlugin {
    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), identity::Error> {
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _callbacks: impl age_plugin::Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let transport = default_daemon_transport().map_err(|e| io::Error::other(e.to_string()))?;

        let mut out = HashMap::new();
        for (file_index, stanzas) in files.iter().enumerate() {
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                if stanza.tag != "kage" {
                    continue;
                }
                if stanza.args.len() != 2 {
                    out.insert(
                        file_index,
                        Err(vec![identity::Error::Stanza {
                            file_index,
                            stanza_index,
                            message: "invalid stanza args".into(),
                        }]),
                    );
                    break;
                }
                let ks = match wrapped_from_age_stanza(file_index, stanza_index, stanza) {
                    Ok(s) => s,
                    Err(e) => {
                        out.insert(file_index, Err(vec![e]));
                        break;
                    }
                };

                let file_key_bytes = match runtime.block_on(transport.unwrap_key(&ks)) {
                    Ok(fk) => fk,
                    Err(e) => {
                        out.insert(
                            file_index,
                            Err(vec![identity::Error::Stanza {
                                file_index,
                                stanza_index,
                                message: e.to_string(),
                            }]),
                        );
                        break;
                    }
                };
                if file_key_bytes.len() != FILE_KEY_BYTES {
                    out.insert(
                        file_index,
                        Err(vec![identity::Error::Stanza {
                            file_index,
                            stanza_index,
                            message: format!(
                                "invalid file key length {}, expected {}",
                                file_key_bytes.len(),
                                FILE_KEY_BYTES
                            ),
                        }]),
                    );
                    break;
                }
                let mut raw = [0u8; FILE_KEY_BYTES];
                raw.copy_from_slice(&file_key_bytes);
                out.insert(file_index, Ok(FileKey::from(raw)));
                break;
            }
        }

        Ok(out)
    }
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse();

    if let Some(state_machine) = opts.age_plugin {
        age_plugin::run_state_machine(
            &state_machine,
            Some(|| KageRecipientPlugin {
                recipients: Vec::new(),
            }),
            Some(|| KageIdentityPlugin),
        )?;
        return Ok(());
    }

    eprintln!("age-plugin-kage should be invoked by age/rage/sops (via the plugin protocol).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_stanza_roundtrip_shape() {
        let kid = Kid([7u8; 16]);
        let wrapped = KageStanza {
            kid_bech32: kid.to_bech32().unwrap(),
            nonce_b64: BASE64.encode([1u8; 24]),
            payload_b64: BASE64.encode([2u8; 32]),
        };

        let stanza = age_stanza_from_wrapped(&kid, &wrapped).unwrap();
        assert_eq!(stanza.tag, "kage");
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(stanza.args[0], BASE64.encode(kid.0));
        assert_eq!(stanza.args[1], wrapped.nonce_b64);
        assert_eq!(stanza.body, BASE64.decode(wrapped.payload_b64).unwrap());

        let reparsed = match wrapped_from_age_stanza(0, 0, &stanza) {
            Ok(v) => v,
            Err(_) => panic!("wrapped_from_age_stanza failed"),
        };
        assert_eq!(reparsed.kid().unwrap(), kid);
        assert_eq!(reparsed.nonce().unwrap(), [1u8; 24]);
        assert_eq!(reparsed.payload().unwrap(), vec![2u8; 32]);
    }
}
