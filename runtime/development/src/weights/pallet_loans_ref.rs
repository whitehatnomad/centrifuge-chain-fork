
//! Autogenerated weights for `pallet_loans_ref`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-03-09, STEPS: `2`, REPEAT: 1, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `MBP-de-Luis.home`, CPU: `<UNKNOWN>`
//! EXECUTION: None, WASM-EXECUTION: Compiled, CHAIN: Some("development"), DB CACHE: 1024

// Executed Command:
// target/release/centrifuge-chain
// benchmark
// pallet
// --pallet=pallet-loans-ref
// --chain
// development
// --extrinsic=*
// --output=runtime/development/src/weights/pallet_loans_ref.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_loans_ref`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_loans_ref::WeightInfo for WeightInfo<T> {
	// Storage: PoolSystem Pool (r:1 w:0)
	// Storage: InterestAccrual Rates (r:1 w:0)
	// Storage: LoansRef ActiveLoans (r:1 w:0)
	// Storage: Timestamp Now (r:1 w:0)
	// Storage: LoansRef LatestPortfolioValuations (r:0 w:1)
	/// The range of component `n` is `[1, 50]`.
	/// The range of component `m` is `[1, 50]`.
	fn update_portfolio_valuation(n: u32, m: u32, ) -> Weight {
		// Minimum execution time: 33_000 nanoseconds.
		Weight::from_ref_time(33_000_000 as u64)
			// Standard Error: 380_142
			.saturating_add(Weight::from_ref_time(4_619_571 as u64).saturating_mul(n as u64))
			// Standard Error: 380_142
			.saturating_add(Weight::from_ref_time(313_449 as u64).saturating_mul(m as u64))
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
}
