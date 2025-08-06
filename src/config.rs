use std::{env, fs};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Configuration {
    pub logging: Logging,
    pub postgresql: Postgresql,
    pub api: Api,
}

impl Configuration {
    pub fn get(file_path: &str) -> Result<Configuration> {
        info!(path = %file_path, "Loading configuration file");

        let mut content = fs::read_to_string(file_path)?;

        // Replace environment variables in config.
        for (k, v) in env::vars() {
            content = content.replace(&format!("${}", k), &v);
        }

        let config: Configuration = toml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Logging {
    pub level: String,
}

impl Default for Logging {
    fn default() -> Self {
        Logging {
            level: "info".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Postgresql {
    pub dsn: String,
    pub max_open_connections: u32,
    pub ca_cert: String,
}

impl Default for Postgresql {
    fn default() -> Self {
        Postgresql {
            dsn: "postgresql://simple_js:simple_js@localhost/simple_js?sslmode=disable".into(),
            max_open_connections: 10,
            ca_cert: "".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Api {
    pub bind: String,
    pub tls_cert: String,
    pub tls_key: String,
}

impl Default for Api {
    fn default() -> Self {
        Api {
            bind: "0.0.0.0:8070".into(),
            tls_cert: "".into(),
            tls_key: "".into(),
        }
    }
}
