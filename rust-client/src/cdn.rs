//! CDN-looking random poll paths (same idea as cdn_paths.py).

use rand::seq::SliceRandom;
use rand::Rng;

fn hex(n: usize, rng: &mut impl Rng) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    (0..n)
        .map(|_| HEX[rng.gen_range(0..16)] as char)
        .collect()
}

fn digits(n: usize, rng: &mut impl Rng) -> String {
    (0..n).map(|_| char::from(b'0' + rng.gen_range(0..10))).collect()
}

/// Appends a plausible static-asset path to the configured poll path.
pub fn random_cdn_path(poll_path: &str, rng: &mut impl Rng) -> String {
    let base = poll_path.trim_end_matches('/');
    let pick: f64 = rng.gen();
    if pick < 0.18 {
        let ext = *["js", "css"].choose(rng).unwrap();
        let nm = *["app", "main", "vendor", "runtime", "index", "chunk"]
            .choose(rng)
            .unwrap();
        format!("{base}/assets/{nm}.{}.{ext}", hex(6, rng))
    } else if pick < 0.30 {
        let nm = *["app", "main", "index", "styles", "vendor", "bundle"]
            .choose(rng)
            .unwrap();
        let ext = *["js", "css"].choose(rng).unwrap();
        format!("{base}/assets/{nm}.{ext}")
    } else if pick < 0.42 {
        let ext = *["png", "jpg", "webp", "svg", "gif"].choose(rng).unwrap();
        format!("{base}/images/{}.{ext}", digits(rng.gen_range(2..8), rng))
    } else if pick < 0.52 {
        let ext = *["woff2", "woff", "ttf"].choose(rng).unwrap();
        format!("{base}/fonts/{}-{}.{ext}", ["inter", "roboto", "sf", "ibm"].choose(rng).unwrap(), hex(4, rng))
    } else if pick < 0.62 {
        format!("{base}/api/v{}/data.json", rng.gen_range(1..4))
    } else if pick < 0.72 {
        format!("{base}/static/{}/{}.js", hex(2, rng), hex(8, rng))
    } else if pick < 0.82 {
        format!("{base}/media/{}.m3u8", hex(8, rng))
    } else if pick < 0.90 {
        format!("{base}/thumb/{}-{}.jpg", digits(4, rng), hex(6, rng))
    } else {
        format!("{base}/p/{}.{}.js", hex(5, rng), hex(5, rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn always_under_poll_path() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..200 {
            let path = random_cdn_path("/poll", &mut rng);
            assert!(path.starts_with("/poll/"), "{path}");
            assert!(path.len() > "/poll/".len() + 2);
        }
    }
}
