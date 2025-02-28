
//! Autogenerated weights for `pallet_interest_accrual`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-09-05, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `runner`, CPU: `AMD EPYC 7763 64-Core Processor`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("centrifuge-dev"), DB CACHE: 1024

// Executed Command:
// target/release/centrifuge-chain
// benchmark
// pallet
// --chain=centrifuge-dev
// --steps=50
// --repeat=20
// --pallet=pallet_interest_accrual
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=/tmp/runtime/centrifuge/src/weights/pallet_interest_accrual.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_interest_accrual`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_interest_accrual::WeightInfo for WeightInfo<T> {
	/// The range of component `n` is `[1, 25]`.
	fn calculate_accumulated_rate(n: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 671 nanoseconds.
		Weight::from_ref_time(181_268)
			// Standard Error: 392
			.saturating_add(Weight::from_ref_time(645_249).saturating_mul(n.into()))
	}
}
