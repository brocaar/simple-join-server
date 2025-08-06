use std::sync::LazyLock;
use std::sync::Mutex;

use crate::config;
use crate::storage;

static TEST_MUX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub async fn prepare<'a>() -> std::sync::MutexGuard<'a, ()> {
    let guard = TEST_MUX.lock().unwrap();

    let mut conf: config::Configuration = Default::default();
    conf.postgresql.dsn =
        "postgresql://simple_js_test:simple_js_test@localhost/simple_js_test?sslmode=disable"
            .into();

    storage::setup(&conf).await.unwrap();
    storage::reset_db().await.unwrap();

    guard
}
