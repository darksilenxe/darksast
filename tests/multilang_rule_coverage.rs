use std::process::Command;

fn main() {
    let user_input = "echo test";
    let data = b"secret";
    let _ = Command::new("sh").arg("-c").arg(user_input).status();
    let _ = md5::compute(data);
    let _ = reqwest::Client::builder().danger_accept_invalid_certs(true).build();
}
