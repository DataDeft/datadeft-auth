#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use datadeft_pow_core::{PowSecret, Solution, UnixMillis, verify_solution};
#[derive(Arbitrary, Debug)]
struct Input {
    chg: String,
    sol: String,
    non: String,
    dif: u8,
    tim: String,
    tag: String,
    now: u64,
}
fuzz_target!(|input: Input| {
    let solution = Solution {
        chg: input.chg,
        sol: input.sol,
        non: input.non,
        dif: input.dif,
        tim: input.tim,
        tag: input.tag,
    };
    let _ = verify_solution(&PowSecret::new([5u8; 32]), &solution, UnixMillis::from_millis(input.now), 120, 1);
});
