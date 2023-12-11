pub mod default;

#[derive(Debug)]
pub enum Action {
    Default {
        enable: bool,
        disable: bool,
        ipv4: Option<String>,
        leak: bool,
        local: bool,
        print: bool,
    },
}
