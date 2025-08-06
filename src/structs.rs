use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone)]
pub enum MessageType {
    #[default]
    JoinReq,
    JoinAns,
}

#[derive(Default, Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone)]
pub enum ResultCode {
    #[default]
    Success,
    MICFailed,
    JoinReqFailed,
    UnknownDevEUI,
    InvalidProtocolVersion,
    MalformedRequest,
    Other,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BasePayload {
    #[serde(rename = "ProtocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "SenderID", with = "hex_encode")]
    pub sender_id: Vec<u8>,
    #[serde(rename = "ReceiverID", with = "hex_encode")]
    pub receiver_id: Vec<u8>,
    #[serde(rename = "TransactionID")]
    pub transaction_id: u32,
    #[serde(rename = "MessageType")]
    pub message_type: MessageType,
    #[serde(
        default,
        rename = "SenderToken",
        with = "hex_encode",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sender_token: Vec<u8>,
    #[serde(
        default,
        rename = "ReceiverToken",
        with = "hex_encode",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub receiver_token: Vec<u8>,
}

impl Default for BasePayload {
    fn default() -> Self {
        BasePayload {
            protocol_version: "1.0".into(),
            sender_id: "".into(),
            receiver_id: "".into(),
            transaction_id: 0,
            message_type: MessageType::default(),
            sender_token: vec![],
            receiver_token: vec![],
        }
    }
}

impl BasePayload {
    pub fn to_base_payload_result(
        &self,
        res_code: ResultCode,
        description: &str,
    ) -> BasePayloadResult {
        BasePayloadResult {
            base: BasePayload {
                protocol_version: self.protocol_version.clone(),
                sender_id: self.receiver_id.clone(),
                receiver_id: self.sender_id.clone(),
                transaction_id: self.transaction_id,
                message_type: match self.message_type {
                    MessageType::JoinReq => MessageType::JoinAns,
                    _ => self.message_type,
                },
                sender_token: self.receiver_token.clone(),
                receiver_token: self.sender_token.clone(),
            },
            result: ResultPayload {
                result_code: res_code,
                description: description.to_string(),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct BasePayloadResult {
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "Result")]
    pub result: ResultPayload,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone)]
pub struct ResultPayload {
    #[serde(rename = "ResultCode")]
    pub result_code: ResultCode,
    #[serde(
        default,
        rename = "Description",
        skip_serializing_if = "String::is_empty"
    )]
    pub description: String,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JoinReqPayload {
    #[serde(flatten)]
    pub base: BasePayload,
    #[serde(rename = "MACVersion")]
    pub mac_version: String,
    #[serde(rename = "PHYPayload", with = "hex_encode")]
    pub phy_payload: Vec<u8>,
    #[serde(rename = "DevEUI", with = "hex_encode")]
    pub dev_eui: Vec<u8>,
    #[serde(rename = "DevAddr", with = "hex_encode")]
    pub dev_addr: Vec<u8>,
    #[serde(rename = "DLSettings", with = "hex_encode")]
    pub dl_settings: Vec<u8>,
    #[serde(rename = "RxDelay")]
    pub rx_delay: u8,
    #[serde(
        default,
        rename = "CFList",
        with = "hex_encode",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cf_list: Vec<u8>,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JoinAnsPayload {
    #[serde(flatten)]
    pub base: BasePayloadResult,
    #[serde(rename = "PHYPayload", with = "hex_encode")]
    pub phy_payload: Vec<u8>,
    #[serde(rename = "Lifetime", skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<usize>,
    #[serde(rename = "SNwkSIntKey", skip_serializing_if = "Option::is_none")]
    pub s_nwk_s_int_key: Option<KeyEnvelope>,
    #[serde(rename = "FNwkSIntKey", skip_serializing_if = "Option::is_none")]
    pub f_nwk_s_int_key: Option<KeyEnvelope>,
    #[serde(rename = "NwkSEncKey", skip_serializing_if = "Option::is_none")]
    pub nwk_s_enc_key: Option<KeyEnvelope>,
    #[serde(rename = "NwkSKey", skip_serializing_if = "Option::is_none")]
    pub nwk_s_key: Option<KeyEnvelope>,
    #[serde(rename = "AppSKey", skip_serializing_if = "Option::is_none")]
    pub app_s_key: Option<KeyEnvelope>,
    #[serde(
        default,
        rename = "SessionKeyID",
        with = "hex_encode",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_key_id: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct KeyEnvelope {
    #[serde(default, rename = "KEKLabel")]
    pub kek_label: String,
    #[serde(rename = "AESKey", with = "hex_encode")]
    pub aes_key: Vec<u8>,
}

mod hex_encode {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(b: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'a, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let s: &str = serde::de::Deserialize::deserialize(deserializer)?;

        // HEX encoded values may start with 0x prefix, we must strip this.
        let s = s.trim_start_matches("0x");

        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
