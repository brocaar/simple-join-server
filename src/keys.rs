use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use anyhow::Result;

pub fn get_js_int_key(dev_eui: lrwn::EUI64, nwk_key: lrwn::AES128Key) -> Result<lrwn::AES128Key> {
    get_js_key(0x06, dev_eui, nwk_key)
}

/// For LoRaWAN 1.0: SNwkSIntKey = NwkSEncKey = FNwkSIntKey = NwkSKey
pub fn get_f_nwk_s_int_key(
    opt_neg: bool,
    nwk_key: lrwn::AES128Key,
    net_id: lrwn::NetID,
    join_eui: lrwn::EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<lrwn::AES128Key> {
    get_s_key(
        opt_neg, 0x01, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_app_s_key(
    opt_neg: bool,
    nwk_key: lrwn::AES128Key,
    net_id: lrwn::NetID,
    join_eui: lrwn::EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<lrwn::AES128Key> {
    get_s_key(
        opt_neg, 0x02, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_s_nwk_s_int_key(
    opt_neg: bool,
    nwk_key: lrwn::AES128Key,
    net_id: lrwn::NetID,
    join_eui: lrwn::EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<lrwn::AES128Key> {
    get_s_key(
        opt_neg, 0x03, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

pub fn get_nwk_s_enc_key(
    opt_neg: bool,
    nwk_key: lrwn::AES128Key,
    net_id: lrwn::NetID,
    join_eui: lrwn::EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<lrwn::AES128Key> {
    get_s_key(
        opt_neg, 0x04, nwk_key, net_id, join_eui, join_nonce, dev_nonce,
    )
}

fn get_js_key(typ: u8, dev_eui: lrwn::EUI64, nwk_key: lrwn::AES128Key) -> Result<lrwn::AES128Key> {
    let key_bytes = nwk_key.to_bytes();
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes128::new(key);

    let mut b: [u8; 16] = [0; 16];
    b[0] = typ;
    b[1..9].clone_from_slice(&dev_eui.to_le_bytes());

    let block = Block::from_mut_slice(&mut b);
    cipher.encrypt_block(block);

    Ok(lrwn::AES128Key::from_slice(block)?)
}

fn get_s_key(
    opt_neg: bool,
    typ: u8,
    nwk_key: lrwn::AES128Key,
    net_id: lrwn::NetID,
    join_eui: lrwn::EUI64,
    join_nonce: u32,
    dev_nonce: u16,
) -> Result<lrwn::AES128Key> {
    let key_bytes = nwk_key.to_bytes();
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes128::new(key);

    let mut b: [u8; 16] = [0; 16];

    b[0] = typ;
    if opt_neg {
        b[1..4].clone_from_slice(&join_nonce.to_le_bytes()[0..3]);
        b[4..12].clone_from_slice(&join_eui.to_le_bytes());
        b[12..14].clone_from_slice(&dev_nonce.to_le_bytes()[0..2]);
    } else {
        b[1..4].clone_from_slice(&join_nonce.to_le_bytes()[0..3]);
        b[4..7].clone_from_slice(&net_id.to_le_bytes());
        b[7..9].clone_from_slice(&dev_nonce.to_le_bytes()[0..2]);
    }

    let block = Block::from_mut_slice(&mut b);
    cipher.encrypt_block(block);

    Ok(lrwn::AES128Key::from_slice(block)?)
}
