use std::fs::File;
use std::io::BufReader;

use anyhow::{Context, Result};

// Return root certificates, optionally with the provided ca_file appended.
pub fn get_root_certs(ca_file: Option<String>) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert)?;
    }

    if let Some(ca_file) = &ca_file {
        let f = File::open(ca_file).context("Open CA certificate")?;
        let mut reader = BufReader::new(f);
        let certs = rustls_pemfile::certs(&mut reader);
        for cert in certs.flatten() {
            roots.add(cert)?;
        }
    }

    Ok(roots)
}
