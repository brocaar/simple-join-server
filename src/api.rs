use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use axum::{
    body::Bytes,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use tracing::{info, span, warn, Instrument, Level};

use crate::config::Configuration;
use crate::errors::Error;
use crate::keys;
use crate::storage;
use crate::structs;

pub async fn setup(conf: &Configuration) -> Result<()> {
    let addr: SocketAddr = conf.api.bind.parse()?;
    let app = Router::new().fallback(handle_request);

    if conf.api.tls_cert.is_empty() && conf.api.tls_key.is_empty() {
        info!(bind = %addr, "Starting HTTP API interface");
        serve_http(addr, app).await?;
    } else {
        info!(bind = %addr, tls_cert = %conf.api.tls_cert, tls_key = %conf.api.tls_key, "Starting HTTPS API interface");
        serve_https(addr, &conf.api.tls_cert, &conf.api.tls_key, app).await?;
    }

    Ok(())
}

async fn serve_http(addr: SocketAddr, app: Router) -> Result<()> {
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn serve_https(addr: SocketAddr, tls_cert: &str, tls_key: &str, app: Router) -> Result<()> {
    let config =
        RustlsConfig::from_pem_file(PathBuf::from(tls_cert), PathBuf::from(tls_key)).await?;

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn handle_request(headers: HeaderMap, b: Bytes) -> Response {
    let b: Vec<u8> = b.into();

    let auth_token = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => {
            return (StatusCode::UNAUTHORIZED, "Authorization header is missing").into_response();
        }
    }
    .to_str()
    .unwrap_or_default();
    let auth_token = auth_token.replace("Bearer", "");
    let auth_token = auth_token.trim();

    let bp: structs::BasePayload = match serde_json::from_slice(&b) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };

    let ns = match storage::get_ns_by_net_id_and_token(&bp.sender_id, auth_token).await {
        Ok(v) => v,
        Err(e) => {
            warn!(sender_id = %hex::encode(&bp.sender_id), error = %e, "Getting network-server for sender_id and auth. token failed");
            return Json(err_to_response(e, &bp)).into_response();
        }
    };

    let span = span!(Level::INFO, "request", ns_id = %ns.id, sender_id = %hex::encode(&bp.sender_id), receiver_id = %hex::encode(&bp.receiver_id), message_type = ?bp.message_type, transaction_id = bp.transaction_id);
    _handle_request(bp, b, &ns).instrument(span).await
}

async fn _handle_request(
    bp: structs::BasePayload,
    b: Vec<u8>,
    ns: &storage::NetworkServer,
) -> Response {
    let res = match bp.message_type {
        structs::MessageType::JoinReq => handle_join_req(b, ns).await,
        _ => Ok(Json(err_to_response(
            Error::InvalidRequest("Invalid MessageType".into()),
            &bp,
        ))
        .into_response()),
    };

    match res {
        Ok(v) => v,
        Err(e) => Json(err_to_response(e, &bp)).into_response(),
    }
}

async fn handle_join_req(b: Vec<u8>, ns: &storage::NetworkServer) -> Result<Response, Error> {
    let jr_pl: structs::JoinReqPayload = serde_json::from_slice(&b)?;
    let mac_version = if jr_pl.mac_version.starts_with("1.1") {
        lrwn::MACVersion::LoRaWAN1_1
    } else {
        lrwn::MACVersion::LoRaWAN1_0
    };

    let jr_phy = lrwn::PhyPayload::from_slice(&jr_pl.phy_payload)?;
    let jr_phy_pl = if let lrwn::Payload::JoinRequest(pl) = &jr_phy.payload {
        *pl
    } else {
        return Err(Error::InvalidRequest(
            "PhyPayload does not contain JoinRequest".into(),
        ));
    };

    let home_netid = lrwn::NetID::from_slice(&jr_pl.base.sender_id)?;
    let devaddr = lrwn::DevAddr::from_slice(&jr_pl.dev_addr)?;
    let device = storage::validate_dev_nonce_and_get_device(ns, &jr_phy).await?;
    let dl_settings =
        lrwn::DLSettings::from_le_bytes([jr_pl.dl_settings.first().cloned().unwrap_or_default()]);

    let mut ja_phy = lrwn::PhyPayload {
        mhdr: lrwn::MHDR {
            f_type: lrwn::FType::JoinAccept,
            major: lrwn::Major::LoRaWANR1,
        },
        payload: lrwn::Payload::JoinAccept(lrwn::JoinAcceptPayload {
            join_nonce: device.join_nonce as u32,
            home_netid,
            devaddr,
            dl_settings,
            rx_delay: jr_pl.rx_delay as u8,
            cflist: if jr_pl.cf_list.is_empty() {
                None
            } else if jr_pl.cf_list.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&jr_pl.cf_list);
                Some(lrwn::CFList::from_bytes(b)?)
            } else {
                return Err(Error::InvalidRequest("Invalid CFList length".into()));
            },
        }),
        mic: None,
    };

    match mac_version {
        lrwn::MACVersion::LoRaWAN1_0 => {
            ja_phy.set_join_accept_mic(
                lrwn::JoinType::Join,
                &jr_phy_pl.join_eui,
                jr_phy_pl.dev_nonce,
                &device.nwk_key,
            )?;
        }
        lrwn::MACVersion::LoRaWAN1_1 => {
            let js_int_key = keys::get_js_int_key(device.dev_eui, device.nwk_key)?;

            ja_phy.set_join_accept_mic(
                lrwn::JoinType::Join,
                &jr_phy_pl.join_eui,
                jr_phy_pl.dev_nonce,
                &js_int_key,
            )?;
        }
    }
    ja_phy.encrypt_join_accept_payload(&device.nwk_key)?;

    let ja_pl = structs::JoinAnsPayload {
        base: jr_pl
            .base
            .to_base_payload_result(structs::ResultCode::Success, ""),
        phy_payload: ja_phy.to_vec()?,
        s_nwk_s_int_key: match mac_version {
            lrwn::MACVersion::LoRaWAN1_0 => None,
            lrwn::MACVersion::LoRaWAN1_1 => Some(structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: keys::get_s_nwk_s_int_key(
                    true,
                    device.nwk_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                )?
                .to_vec(),
            }),
        },
        f_nwk_s_int_key: match mac_version {
            lrwn::MACVersion::LoRaWAN1_0 => None,
            lrwn::MACVersion::LoRaWAN1_1 => Some(structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: keys::get_f_nwk_s_int_key(
                    true,
                    device.nwk_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                )?
                .to_vec(),
            }),
        },
        nwk_s_enc_key: match mac_version {
            lrwn::MACVersion::LoRaWAN1_0 => None,
            lrwn::MACVersion::LoRaWAN1_1 => Some(structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: keys::get_nwk_s_enc_key(
                    true,
                    device.nwk_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                )?
                .to_vec(),
            }),
        },
        nwk_s_key: match mac_version {
            lrwn::MACVersion::LoRaWAN1_0 => Some(structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: keys::get_f_nwk_s_int_key(
                    false,
                    device.nwk_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                )?
                .to_vec(),
            }),
            lrwn::MACVersion::LoRaWAN1_1 => None,
        },
        app_s_key: Some(structs::KeyEnvelope {
            kek_label: "".into(),
            aes_key: match mac_version {
                lrwn::MACVersion::LoRaWAN1_0 => keys::get_app_s_key(
                    false,
                    device.nwk_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                ),
                lrwn::MACVersion::LoRaWAN1_1 => keys::get_app_s_key(
                    true,
                    device.app_key,
                    home_netid,
                    jr_phy_pl.join_eui,
                    device.join_nonce as u32,
                    jr_phy_pl.dev_nonce,
                ),
            }?
            .to_vec(),
        }),
        ..Default::default()
    };

    Ok(Json(&ja_pl).into_response())
}

fn err_to_response(e: Error, bp: &structs::BasePayload) -> structs::BasePayloadResult {
    let msg = format!("{}", e);
    bp.to_base_payload_result(err_to_result_code(e), &msg)
}

fn err_to_result_code(e: Error) -> structs::ResultCode {
    match e {
        Error::NotFound(_) => structs::ResultCode::UnknownDevEUI,
        Error::InvalidRequest(_) => structs::ResultCode::MalformedRequest,
        _ => structs::ResultCode::Other,
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use diesel_async::RunQueryDsl;

    use super::*;
    use crate::schema;
    use crate::test;

    async fn create_ns_device() -> (storage::NetworkServer, storage::Device) {
        let mut c = storage::get_db_conn().await.unwrap();

        let ns: storage::NetworkServer = diesel::insert_into(schema::network_server::table)
            .values(&storage::NetworkServer {
                id: uuid::Uuid::new_v4(),
                net_id: vec![1, 2, 3],
                name: "test-ns".into(),
                auth_token: "super-secret-auth-token".into(),
            })
            .get_result(&mut c)
            .await
            .unwrap();

        let dev: storage::Device = diesel::insert_into(schema::device::table)
            .values(&storage::Device {
                dev_eui: lrwn::EUI64::from_str("0102030405060708").unwrap(),
                name: "test-device".into(),
                nwk_key: lrwn::AES128Key::from_str("01020304050607080102030405060708").unwrap(),
                ..Default::default()
            })
            .get_result(&mut c)
            .await
            .unwrap();

        diesel::insert_into(schema::network_server_device::table)
            .values(&storage::NetworkServerDevice {
                network_server_id: ns.id.clone(),
                device_dev_eui: dev.dev_eui.clone(),
            })
            .execute(&mut c)
            .await
            .unwrap();

        (ns, dev)
    }

    #[tokio::test]
    async fn test_auth_header() {
        let _guard = test::prepare().await;

        let resp = handle_request(HeaderMap::new(), Bytes::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let (ns, _dev) = create_ns_device().await;

        let mut hm = HeaderMap::new();
        hm.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", ns.auth_token).parse().unwrap(),
        );

        let resp = handle_request(hm, Bytes::new()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_join_req() {
        let _guard = test::prepare().await;
        let (ns, dev) = create_ns_device().await;

        let mut hm = HeaderMap::new();
        hm.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", ns.auth_token).parse().unwrap(),
        );

        let mut phy = lrwn::PhyPayload {
            mhdr: lrwn::MHDR {
                f_type: lrwn::FType::JoinRequest,
                major: lrwn::Major::LoRaWANR1,
            },
            payload: lrwn::Payload::JoinRequest(lrwn::JoinRequestPayload {
                join_eui: dev.dev_eui.clone(),
                dev_eui: dev.dev_eui.clone(),
                dev_nonce: 1,
            }),
            mic: None,
        };
        phy.set_join_request_mic(&dev.nwk_key).unwrap();

        let jr_pl = structs::JoinReqPayload {
            base: structs::BasePayload {
                protocol_version: "1.0".into(),
                sender_id: ns.net_id.clone(),
                receiver_id: dev.dev_eui.to_vec(),
                message_type: structs::MessageType::JoinReq,
                ..Default::default()
            },
            mac_version: "1.0.4".into(),
            phy_payload: phy.to_vec().unwrap(),
            dev_eui: dev.dev_eui.to_vec(),
            dev_addr: vec![4, 3, 2, 1],
            dl_settings: vec![0x00],
            rx_delay: 3,
            cf_list: vec![],
        };

        let resp = handle_request(hm, serde_json::to_vec(&jr_pl).unwrap().into()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let ja_pl: structs::JoinAnsPayload = serde_json::from_slice(&resp_b).unwrap();

        assert_eq!(structs::MessageType::JoinAns, ja_pl.base.base.message_type);
        assert_eq!("", ja_pl.base.result.description);
        assert_eq!(structs::ResultCode::Success, ja_pl.base.result.result_code);

        let mut ja_phy = lrwn::PhyPayload::from_slice(&ja_pl.phy_payload).unwrap();
        ja_phy.decrypt_join_accept_payload(&dev.nwk_key).unwrap();

        assert!(ja_phy
            .validate_join_accept_mic(lrwn::JoinType::Join, &dev.dev_eui, 1, &dev.nwk_key)
            .unwrap());

        if let lrwn::Payload::JoinAccept(pl) = ja_phy.payload {
            assert_eq!(1, pl.join_nonce);
            assert_eq!(lrwn::NetID::from_str("010203").unwrap(), pl.home_netid);
            assert_eq!(lrwn::DevAddr::from_str("04030201").unwrap(), pl.devaddr);
            assert_eq!(
                lrwn::DLSettings {
                    opt_neg: false,
                    rx2_dr: 0,
                    rx1_dr_offset: 0
                },
                pl.dl_settings
            );
            assert_eq!(3, pl.rx_delay);
            assert!(pl.cflist.is_none());
        } else {
            assert!(false);
        }

        assert!(ja_pl.s_nwk_s_int_key.is_none());
        assert!(ja_pl.f_nwk_s_int_key.is_none());
        assert!(ja_pl.nwk_s_enc_key.is_none());

        assert_eq!(
            structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: vec![
                    108, 63, 204, 213, 99, 243, 177, 140, 77, 153, 169, 179, 240, 51, 87, 68
                ],
            },
            ja_pl.nwk_s_key.unwrap()
        );

        assert_eq!(
            structs::KeyEnvelope {
                kek_label: "".into(),
                aes_key: vec![
                    98, 35, 15, 69, 187, 110, 196, 7, 0, 115, 65, 246, 92, 243, 205, 141,
                ],
            },
            ja_pl.app_s_key.unwrap()
        );
    }
}
