// Copyright 2023 Centrifuge Foundation (centrifuge.io).
// This file is part of Centrifuge chain project.

// Centrifuge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version (see http://www.gnu.org/licenses).

// Centrifuge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

use cfg_traits::data::{DataCollection, DataRegistry};
use frame_support::{assert_noop, assert_ok, pallet_prelude::Hooks};
use orml_traits::DataFeeder;

use super::{mock::*, pallet::Error};

const COLLECTION_ID: CollectionId = 1;
const DATA_ID: DataId = 10;

fn advance_time(elapsed: u64) {
	Timer::set_timestamp(Timer::get() + elapsed);
}

fn feed(data_id: DataId, data: Data) {
	// For testing we want to skip the limitiation of one feed call per block
	Oracle::on_finalize(0);
	Oracle::feed_value(ORACLE_MEMBER, data_id, data).unwrap();
}

#[test]
fn feed_and_then_register() {
	new_test_ext().execute_with(|| {
		feed(DATA_ID, 100);

		assert_noop!(
			DataCollector::get(&DATA_ID, &COLLECTION_ID),
			Error::<Runtime>::DataIdNotInCollection
		);

		assert_ok!(DataCollector::register_id(&DATA_ID, &COLLECTION_ID));

		assert_ok!(
			DataCollector::collection(&COLLECTION_ID).get(&DATA_ID),
			(100, Timer::now())
		);

		assert_eq!(
			DataCollector::get(&DATA_ID, &COLLECTION_ID),
			Ok((100, Timer::now()))
		);

		advance_time(BLOCK_TIME_MS);
		feed(DATA_ID, 200);

		assert_ok!(
			DataCollector::collection(&COLLECTION_ID).get(&DATA_ID),
			(200, Timer::now())
		);

		assert_eq!(
			DataCollector::get(&DATA_ID, &COLLECTION_ID),
			Ok((200, Timer::now()))
		);
	});
}

#[test]
fn register_without_feed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			DataCollector::register_id(&DATA_ID, &COLLECTION_ID),
			Error::<Runtime>::DataIdWithoutData
		);
	});
}

#[test]
fn data_not_registered_in_collection() {
	new_test_ext().execute_with(|| {
		feed(DATA_ID, 100);
		feed(DATA_ID + 1, 100);

		assert_ok!(DataCollector::register_id(&DATA_ID, &COLLECTION_ID));

		let collection = DataCollector::collection(&COLLECTION_ID);
		assert_noop!(
			collection.get(&(DATA_ID + 1)),
			Error::<Runtime>::DataIdNotInCollection
		);
	});
}

#[test]
fn data_not_registered_after_unregister() {
	new_test_ext().execute_with(|| {
		feed(DATA_ID, 100);

		assert_ok!(DataCollector::register_id(&DATA_ID, &COLLECTION_ID));

		assert_ok!(DataCollector::unregister_id(&DATA_ID, &COLLECTION_ID));

		let collection = DataCollector::collection(&COLLECTION_ID);
		assert_noop!(
			collection.get(&DATA_ID),
			Error::<Runtime>::DataIdNotInCollection
		);
	});
}

#[test]
fn unregister_without_register() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			DataCollector::unregister_id(&DATA_ID, &COLLECTION_ID),
			Error::<Runtime>::DataIdNotInCollection
		);
	});
}

#[test]
fn register_twice() {
	new_test_ext().execute_with(|| {
		feed(DATA_ID, 100);

		assert_ok!(DataCollector::register_id(&DATA_ID, &COLLECTION_ID));

		assert_ok!(DataCollector::register_id(&DATA_ID, &COLLECTION_ID));

		assert_ok!(DataCollector::unregister_id(&DATA_ID, &COLLECTION_ID));

		assert_ok!(DataCollector::unregister_id(&DATA_ID, &COLLECTION_ID));

		assert_noop!(
			DataCollector::unregister_id(&DATA_ID, &COLLECTION_ID),
			Error::<Runtime>::DataIdNotInCollection
		);
	});
}

#[test]
fn max_collection_number() {
	new_test_ext().execute_with(|| {
		feed(DATA_ID, 100);

		let max = MaxCollections::get() as CollectionId;
		for i in 0..max {
			assert_ok!(DataCollector::register_id(&DATA_ID, &(COLLECTION_ID + i)));
		}

		assert_noop!(
			DataCollector::register_id(&DATA_ID, &(COLLECTION_ID + max)),
			Error::<Runtime>::MaxCollectionNumber
		);
	});
}

#[test]
fn max_collection_size() {
	new_test_ext().execute_with(|| {
		let max = MaxCollectionSize::get();
		for i in 0..max {
			feed(DATA_ID + i, 100);
			assert_ok!(DataCollector::register_id(&(DATA_ID + i), &COLLECTION_ID));
		}

		feed(DATA_ID + max, 100);
		assert_noop!(
			DataCollector::register_id(&(DATA_ID + max), &COLLECTION_ID),
			Error::<Runtime>::MaxCollectionSize
		);

		// Other collections can still be registered
		assert_ok!(DataCollector::register_id(&DATA_ID, &(COLLECTION_ID + 1)));
	});
}
