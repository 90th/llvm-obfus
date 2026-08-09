use std::env;
use std::time::Instant;

#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_protected_mix(seed: u64) -> u64 {
    let secret = b"rust-bench-visible-secret\0";
    let mut state = seed.rotate_left(7) ^ 0x9e37_79b9_7f4a_7c15;

    for (index, byte) in secret[..secret.len() - 1].iter().enumerate() {
        let shift = ((index & 7) * 8) as u32;
        let lane = ((*byte as u64) << shift) ^ ((index as u64 + 1) * 0x45d9_f3b);
        if ((state ^ lane) & 1) == 0 {
            state = state.rotate_left(9).wrapping_add(lane);
        } else {
            state = state.rotate_right(3) ^ lane.wrapping_mul(17);
        }
    }

    state ^ 0x6a09_e667_f3bc_c909
}

#[inline(never)]
fn fold_value(value: u64) -> u64 {
    value.rotate_left(11) ^ 0xa5a5_a5a5_5a5a_5a5a
}

fn bench_iters() -> u64 {
    match env::var("OBF_BENCH_ITERS") {
        Ok(text) => text.parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    }
}

fn run_once(seed: u64) -> u64 {
    fold_value(rust_protected_mix(seed))
}

fn main() {
    let base_seed = env::args()
        .nth(1)
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(7);
    let iters = bench_iters();

    if iters > 0 {
        let mut sink = 0u64;
        for i in 0..2048u64 {
            sink ^= run_once(base_seed.wrapping_add(i.wrapping_mul(3)));
        }

        let start = Instant::now();
        for i in 0..iters {
            sink ^= run_once(base_seed.wrapping_add(i.wrapping_mul(3)));
        }
        let total_ns = start.elapsed().as_nanos();
        let ns_per_iter = total_ns / u128::from(iters);
        println!("BENCH rust_demo ns/op={} sink={}", ns_per_iter, sink);
        return;
    }

    println!("rust={}", run_once(base_seed));
}
