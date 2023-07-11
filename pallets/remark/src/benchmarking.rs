// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Benchmarks for Utility Pallet

#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::v1::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;

use super::*;

const SEED: u32 = 0;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

benchmarks! {
	where_clause { where <T::RuntimeOrigin as frame_support::traits::OriginTrait>::PalletsOrigin: Clone }
	remark {
		let c in 0 .. 1000;
		let remark = Default::default();
		let mut calls: Vec<<T as Config>::RuntimeCall> = Vec::new();
		for i in 0 .. c {
			let call = frame_system::Call::remark { remark: vec![] }.into();
			calls.push(call);
		}
		let caller = whitelisted_caller();
	}: _(RawOrigin::Signed(caller), calls)
	verify {
		assert_last_event::<T>(Event::Remark{ remark, calls }.into())
	}

	impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
