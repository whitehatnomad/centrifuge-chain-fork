
//! Autogenerated weights for `pallet_restricted_tokens`
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
// --pallet=pallet_restricted_tokens
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=/tmp/runtime/centrifuge/src/weights/pallet_restricted_tokens.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `pallet_restricted_tokens`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_restricted_tokens::WeightInfo for WeightInfo<T> {
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `2603`
		// Minimum execution time: 54_401 nanoseconds.
		Weight::from_parts(54_932_000, 2603)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: OrmlTokens Accounts (r:2 w:2)
	/// Proof: OrmlTokens Accounts (max_values: None, max_size: Some(129), added: 2604, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `573`
		//  Estimated: `7811`
		// Minimum execution time: 56_395 nanoseconds.
		Weight::from_parts(56_996_000, 7811)
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_keep_alive_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `2603`
		// Minimum execution time: 47_158 nanoseconds.
		Weight::from_parts(48_039_000, 2603)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: OrmlTokens Accounts (r:2 w:2)
	/// Proof: OrmlTokens Accounts (max_values: None, max_size: Some(129), added: 2604, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_keep_alive_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `438`
		//  Estimated: `7811`
		// Minimum execution time: 52_206 nanoseconds.
		Weight::from_parts(53_319_000, 7811)
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_all_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `2603`
		// Minimum execution time: 57_527 nanoseconds.
		Weight::from_parts(58_819_000, 2603)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: OrmlTokens Accounts (r:2 w:2)
	/// Proof: OrmlTokens Accounts (max_values: None, max_size: Some(129), added: 2604, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn transfer_all_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `573`
		//  Estimated: `7811`
		// Minimum execution time: 59_250 nanoseconds.
		Weight::from_parts(60_302_000, 7811)
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn force_transfer_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `224`
		//  Estimated: `2603`
		// Minimum execution time: 53_970 nanoseconds.
		Weight::from_parts(54_811_000, 2603)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: OrmlTokens Accounts (r:2 w:2)
	/// Proof: OrmlTokens Accounts (max_values: None, max_size: Some(129), added: 2604, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn force_transfer_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `573`
		//  Estimated: `7811`
		// Minimum execution time: 55_873 nanoseconds.
		Weight::from_parts(57_136_000, 7811)
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn set_balance_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `89`
		//  Estimated: `2603`
		// Minimum execution time: 51_626 nanoseconds.
		Weight::from_parts(53_179_000, 2603)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: OrmlTokens Accounts (r:1 w:1)
	/// Proof: OrmlTokens Accounts (max_values: None, max_size: Some(129), added: 2604, mode: MaxEncodedLen)
	/// Storage: OrmlTokens TotalIssuance (r:1 w:1)
	/// Proof: OrmlTokens TotalIssuance (max_values: None, max_size: Some(49), added: 2524, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn set_balance_other() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `302`
		//  Estimated: `7731`
		// Minimum execution time: 69_349 nanoseconds.
		Weight::from_parts(70_301_000, 7731)
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}
