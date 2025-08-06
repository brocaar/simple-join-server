use handlebars::Handlebars;

use crate::config::Configuration;

const TEMPLATE: &str = include_str!("simple-join-server.toml");

pub fn run(conf: &Configuration) {
    let mut reg = Handlebars::new();
    reg.register_escape_fn(|s| s.to_string().replace('"', r#"\""#));
    println!(
        "{}",
        reg.render_template(TEMPLATE, &conf)
            .expect("render configfile error")
    );
}
