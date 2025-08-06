use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use anyhow::Result;
use diesel::{
    backend::Backend, deserialize, pg::Pg, prelude::*, serialize, sql_types::Jsonb,
    ConnectionError, ConnectionResult,
};
use diesel_async::{
    async_connection_wrapper::AsyncConnectionWrapper,
    pooled_connection::{
        deadpool::{Object as DeadpoolObject, Pool as DeadpoolPool},
        {AsyncDieselConnectionManager, ManagerConfig},
    },
    AsyncConnection, AsyncPgConnection, RunQueryDsl,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use futures::{future::BoxFuture, FutureExt};
use lrwn::{AES128Key, EUI64};
use scoped_futures::ScopedBoxFuture;
use tracing::{error, info};
use uuid::Uuid;

use crate::config::Configuration;
use crate::errors::Error;
use crate::helpers::get_root_certs;
use crate::schema::{device, network_server, network_server_device};

pub type PgPool = DeadpoolPool<AsyncPgConnection>;
pub type PgPoolConnection = DeadpoolObject<AsyncPgConnection>;

static CA_CERT: LazyLock<RwLock<Option<String>>> = LazyLock::new(|| RwLock::new(None));
static PG_POOL: LazyLock<RwLock<Option<PgPool>>> = LazyLock::new(|| RwLock::new(None));

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[derive(Default, Debug, Clone, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = Jsonb)]
pub struct DevNonces(HashMap<EUI64, Vec<u16>>);

impl DevNonces {
    pub fn contains(&self, join_eui: EUI64, dev_nonce: u16) -> bool {
        if let Some(v) = self.0.get(&join_eui) {
            v.contains(&dev_nonce)
        } else {
            false
        }
    }

    pub fn insert(&mut self, join_eui: EUI64, dev_nonce: u16) {
        self.0.entry(join_eui).or_default().push(dev_nonce)
    }
}

impl deserialize::FromSql<Jsonb, Pg> for DevNonces {
    fn from_sql(value: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let value = <serde_json::Value as deserialize::FromSql<Jsonb, Pg>>::from_sql(value)?;
        let dev_nonces: HashMap<EUI64, Vec<u16>> = serde_json::from_value(value)?;
        Ok(DevNonces(dev_nonces))
    }
}

impl serialize::ToSql<Jsonb, Pg> for DevNonces {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, Pg>) -> serialize::Result {
        let value = serde_json::to_value(&self.0)?;
        <serde_json::Value as serialize::ToSql<Jsonb, Pg>>::to_sql(&value, &mut out.reborrow())
    }
}

#[derive(Debug, Clone, Queryable, Insertable)]
#[diesel(table_name = network_server)]
#[allow(dead_code)]
pub struct NetworkServer {
    pub id: Uuid,
    pub net_id: Vec<u8>,
    pub name: String,
    pub auth_token: String,
}

#[derive(Default, Debug, Clone, Queryable, Insertable)]
#[diesel(table_name = device)]
#[allow(dead_code)]
pub struct Device {
    pub dev_eui: EUI64,
    pub name: String,
    pub nwk_key: AES128Key,
    pub app_key: AES128Key,
    pub join_nonce: i32,
    pub dev_nonces: DevNonces,
}

#[derive(Debug, Clone, Queryable, Insertable)]
#[diesel(table_name = network_server_device)]
#[allow(dead_code)]
pub struct NetworkServerDevice {
    pub network_server_id: Uuid,
    pub device_dev_eui: EUI64,
}

pub async fn setup(conf: &Configuration) -> Result<()> {
    info!("Setting up PostgreSQL connection pool");

    if !conf.postgresql.ca_cert.is_empty() {
        let mut ca_cert = CA_CERT.write().unwrap();
        *ca_cert = Some(conf.postgresql.ca_cert.clone());
    }

    let mut config = ManagerConfig::default();
    config.custom_setup = Box::new(pg_establish_connection);
    let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(
        &conf.postgresql.dsn,
        config,
    );
    let pool = DeadpoolPool::builder(mgr)
        .max_size(conf.postgresql.max_open_connections as usize)
        .build()?;
    set_db_pool(pool);
    run_db_migrations().await?;

    Ok(())
}

pub async fn get_ns_by_net_id_and_token(
    net_id: &[u8],
    token: &str,
) -> Result<NetworkServer, Error> {
    network_server::dsl::network_server
        .filter(
            network_server::dsl::net_id
                .eq(net_id)
                .and(network_server::dsl::auth_token.eq(token)),
        )
        .first(&mut get_db_conn().await?)
        .await
        .map_err(|e| Error::from_diesel(e, hex::encode(net_id)))
}

pub async fn validate_dev_nonce_and_get_device(
    ns: &NetworkServer,
    phy: &lrwn::PhyPayload,
) -> Result<Device, Error> {
    if let lrwn::Payload::JoinRequest(pl) = &phy.payload {
        let mut c = get_db_conn().await?;

        db_transaction::<Device, Error, _>(&mut c, |c| {
            Box::pin(async move {
                // get and lock the device.
                let mut d: Device = device::table
                    .select((
                        device::dsl::dev_eui,
                        device::dsl::name,
                        device::dsl::nwk_key,
                        device::dsl::app_key,
                        device::dsl::join_nonce,
                        device::dsl::dev_nonces,
                    ))
                    .inner_join(network_server_device::table)
                    .filter(device::dsl::dev_eui.eq(&pl.dev_eui))
                    .filter(network_server_device::network_server_id.eq(&ns.id))
                    .for_update()
                    .first(c)
                    .await
                    .map_err(|e| Error::from_diesel(e, pl.dev_eui.to_string()))?;

                // Validate MIC.
                phy.validate_join_request_mic(&d.nwk_key)?;

                // Validate Nonce.
                if d.dev_nonces.contains(pl.join_eui, pl.dev_nonce) {
                    return Err(Error::InvalidRequest("DevNonce already used".into()));
                }

                d.dev_nonces.insert(pl.join_eui, pl.dev_nonce);

                // Update the device
                diesel::update(device::table.find(&d.dev_eui))
                    .set((
                        device::dsl::dev_nonces.eq(&d.dev_nonces),
                        device::dsl::join_nonce.eq(d.join_nonce + 1),
                    ))
                    .get_result(c)
                    .await
                    .map_err(|e| Error::from_diesel(e, pl.dev_eui.to_string()))
            })
        })
        .await
    } else {
        Err(Error::InvalidRequest(
            "PhyPayload does not contain JoinRequest".into(),
        ))
    }
}

// Source:
// https://github.com/weiznich/diesel_async/blob/main/examples/postgres/pooled-with-rustls/src/main.rs
fn pg_establish_connection(config: &str) -> BoxFuture<ConnectionResult<AsyncPgConnection>> {
    let fut = async {
        let ca_cert = { CA_CERT.read().unwrap().clone().unwrap_or_default() };
        let root_certs = get_root_certs(if ca_cert.is_empty() {
            None
        } else {
            Some(ca_cert)
        })
        .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;
        let rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(rustls_config);
        let (client, conn) = tokio_postgres::connect(config, tls)
            .await
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!(error = %e, "PostgreSQL connection error");
            }
        });
        AsyncPgConnection::try_from(client).await
    };
    fut.boxed()
}

fn set_db_pool(p: PgPool) {
    let mut pool_w = PG_POOL.write().unwrap();
    *pool_w = Some(p);
}

fn get_db_pool() -> Result<PgPool> {
    let pool_r = PG_POOL.read().unwrap();
    let pool: PgPool = pool_r
        .as_ref()
        .ok_or_else(|| anyhow!("PostgreSQL connection pool is not initialized"))?
        .clone();
    Ok(pool)
}

pub async fn get_db_conn() -> Result<PgPoolConnection> {
    let pool = get_db_pool()?;
    Ok(pool.get().await?)
}

pub async fn db_transaction<'a, R, E, F>(conn: &mut PgPoolConnection, callback: F) -> Result<R, E>
where
    F: for<'r> FnOnce(&'r mut PgPoolConnection) -> ScopedBoxFuture<'a, 'r, Result<R, E>>
        + Send
        + 'a,
    E: From<diesel::result::Error> + Send + 'a,
    R: Send + 'a,
{
    conn.transaction(callback).await
}

async fn run_db_migrations() -> Result<()> {
    info!("Applying schema migrations");

    let c = get_db_conn().await?;
    let mut c_wrapped: AsyncConnectionWrapper<PgPoolConnection> = AsyncConnectionWrapper::from(c);

    tokio::task::spawn_blocking(move || -> Result<()> {
        c_wrapped
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("{}", e))?;

        Ok(())
    })
    .await?
}

#[cfg(test)]
pub async fn reset_db() -> Result<()> {
    let c = get_db_conn().await?;
    let mut c_wrapped: AsyncConnectionWrapper<PgPoolConnection> = AsyncConnectionWrapper::from(c);

    tokio::task::spawn_blocking(move || -> Result<()> {
        c_wrapped
            .revert_all_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("During revert: {}", e))?;
        c_wrapped
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!("During run: {}", e))?;

        Ok(())
    })
    .await?
}
