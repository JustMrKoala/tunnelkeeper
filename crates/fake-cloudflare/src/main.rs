//! Runs the fake API by hand, for trying the CLI without a real account.

use fake_cloudflare::{ALL_PERMS, FakeCloudflare};

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(8787);
    let fake = FakeCloudflare::spawn_on(port);
    fake.add_token("dev-token", ALL_PERMS);
    let zone = fake.add_zone("example.com");
    fake.add_dns(&zone, "A", "taken.example.com", "192.0.2.1", Some("an existing server"));
    fake.use_realistic_tokens();
    println!("fake Cloudflare API at {} with token dev-token and zone example.com", fake.base_url());
    loop {
        std::thread::park();
    }
}
