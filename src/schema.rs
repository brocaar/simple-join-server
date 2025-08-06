// @generated automatically by Diesel CLI.

diesel::table! {
    device (dev_eui) {
        dev_eui -> Bytea,
        name -> Text,
        nwk_key -> Bytea,
        app_key -> Bytea,
        join_nonce -> Int4,
        dev_nonces -> Jsonb,
    }
}

diesel::table! {
    network_server (id) {
        id -> Uuid,
        net_id -> Bytea,
        name -> Text,
        auth_token -> Text,
    }
}

diesel::table! {
    network_server_device (network_server_id, device_dev_eui) {
        network_server_id -> Uuid,
        device_dev_eui -> Bytea,
    }
}

diesel::joinable!(network_server_device -> device (device_dev_eui));
diesel::joinable!(network_server_device -> network_server (network_server_id));

diesel::allow_tables_to_appear_in_same_query!(
    device,
    network_server,
    network_server_device,
);
