create table network_server (
    id uuid primary key,
    net_id bytea not null,
    name text not null,
    auth_token text not null
);

create index idx_network_server_net_id on network_server (net_id);

create table device (
    dev_eui bytea primary key,
    name text not null,
    nwk_key bytea not null,
    app_key bytea not null,
    join_nonce integer not null,
    dev_nonces jsonb not null
);

create table network_server_device (
    network_server_id uuid references network_server,
    device_dev_eui bytea references device,
    primary key (network_server_id, device_dev_eui)
);
