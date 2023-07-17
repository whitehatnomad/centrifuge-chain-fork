use cfg_mocks::*;
use cfg_traits::connectors::{Codec, OutboundQueue};
use cfg_types::{connectors_gateway::EVMAddress, domain_address::*};
use frame_support::{assert_noop, assert_ok};
use sp_core::{crypto::AccountId32, ByteArray, H160};
use sp_runtime::{DispatchError, DispatchError::BadOrigin};

use super::{
	mock::{RuntimeEvent as MockEvent, *},
	origin::*,
	pallet::*,
};

mod utils {
	use super::*;

	pub fn get_test_account_id() -> AccountId32 {
		[0u8; 32].into()
	}

	pub fn event_exists<E: Into<MockEvent>>(e: E) {
		let e: MockEvent = e.into();
		assert!(frame_system::Pallet::<Runtime>::events()
			.iter()
			.any(|ev| ev.event == e));
	}
}

use utils::*;

mod set_domain_router {
	use super::*;

	#[test]
	fn success() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let router = RouterMock::<Runtime>::default();
			router.mock_init(move || Ok(()));

			assert_ok!(ConnectorsGateway::set_domain_router(
				RuntimeOrigin::root(),
				domain.clone(),
				router.clone(),
			));

			let storage_entry = DomainRouters::<Runtime>::get(domain.clone());
			assert_eq!(storage_entry.unwrap(), router);

			event_exists(Event::<Runtime>::DomainRouterSet { domain, router });
		});
	}
	#[test]
	fn router_init_error() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let router = RouterMock::<Runtime>::default();
			router.mock_init(move || Err(DispatchError::Other("error")));

			assert_noop!(
				ConnectorsGateway::set_domain_router(RuntimeOrigin::root(), domain.clone(), router,),
				Error::<Runtime>::RouterInitFailed,
			);
		});
	}

	#[test]
	fn bad_origin() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let router = RouterMock::<Runtime>::default();

			assert_noop!(
				ConnectorsGateway::set_domain_router(
					RuntimeOrigin::signed(get_test_account_id()),
					domain.clone(),
					router,
				),
				BadOrigin
			);

			let storage_entry = DomainRouters::<Runtime>::get(domain);
			assert!(storage_entry.is_none());
		});
	}
}

mod add_connector {
	use super::*;

	#[test]
	fn success() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			assert!(ConnectorsAllowlist::<Runtime>::contains_key(
				domain,
				external_address.clone()
			));

			event_exists(Event::<Runtime>::ConnectorAdded {
				connector: external_address,
			});
		});
	}

	#[test]
	fn bad_origin() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_noop!(
				ConnectorsGateway::add_connector(
					RuntimeOrigin::signed(get_test_account_id()),
					external_address.clone(),
				),
				BadOrigin
			);

			assert!(!ConnectorsAllowlist::<Runtime>::contains_key(
				domain,
				external_address.clone()
			));
		});
	}

	#[test]
	fn connector_already_added() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			assert!(ConnectorsAllowlist::<Runtime>::contains_key(
				domain,
				external_address.clone()
			));

			assert_noop!(
				ConnectorsGateway::add_connector(RuntimeOrigin::root(), external_address),
				Error::<Runtime>::ConnectorAlreadyAdded
			);
		});
	}
}

mod remove_connector {
	use super::*;

	#[test]
	fn success() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			assert_ok!(ConnectorsGateway::remove_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			assert!(!ConnectorsAllowlist::<Runtime>::contains_key(
				domain,
				external_address.clone()
			));

			event_exists(Event::<Runtime>::ConnectorRemoved {
				connector: external_address.clone(),
			});
		});
	}

	#[test]
	fn bad_origin() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_noop!(
				ConnectorsGateway::remove_connector(
					RuntimeOrigin::signed(get_test_account_id()),
					external_address,
				),
				BadOrigin
			);
		});
	}

	#[test]
	fn connector_not_found() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_noop!(
				ConnectorsGateway::remove_connector(RuntimeOrigin::root(), external_address),
				Error::<Runtime>::ConnectorNotFound,
			);
		});
	}
}

mod process_msg {
	use sp_core::bounded::BoundedVec;

	use super::*;

	#[test]
	fn success() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			let expected_msg = MessageMock::First;
			let encoded_msg = expected_msg.serialize();

			MockConnectors::mock_submit(move |mock_external_address, mock_msg| {
				assert_eq!(
					mock_external_address,
					DomainAddress::EVM(0, external_address.address)
				);
				assert_eq!(expected_msg, mock_msg);

				Ok(())
			});

			assert_ok!(ConnectorsGateway::process_msg(
				GatewayOrigin::Local(external_address).into(),
				BoundedVec::<u8, MaxIncomingMessageSize>::try_from(encoded_msg).unwrap()
			));
		});
	}

	#[test]
	fn bad_origin() {
		new_test_ext().execute_with(|| {
			let encoded_msg = MessageMock::First.serialize();

			assert_noop!(
				ConnectorsGateway::process_msg(
					RuntimeOrigin::root(),
					BoundedVec::<u8, MaxIncomingMessageSize>::try_from(encoded_msg).unwrap()
				),
				BadOrigin,
			);
		});
	}

	#[test]
	fn unknown_connector() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};
			let encoded_msg = MessageMock::First.serialize();

			assert_noop!(
				ConnectorsGateway::process_msg(
					GatewayOrigin::Local(external_address).into(),
					BoundedVec::<u8, MaxIncomingMessageSize>::try_from(encoded_msg).unwrap()
				),
				Error::<Runtime>::UnknownConnector,
			);
		});
	}

	#[test]
	fn message_decode_error() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			let encoded_msg: Vec<u8> = vec![11];

			assert_noop!(
				ConnectorsGateway::process_msg(
					GatewayOrigin::Local(external_address).into(),
					BoundedVec::<u8, MaxIncomingMessageSize>::try_from(encoded_msg).unwrap()
				),
				Error::<Runtime>::MessageDecodingFailed,
			);
		});
	}

	#[test]
	fn connectors_error() {
		new_test_ext().execute_with(|| {
			let address = H160::from_slice(&get_test_account_id().as_slice()[..20]);
			let domain = 0;
			let external_address = EVMAddress {
				chain_id: domain,
				address: address.into(),
			};

			assert_ok!(ConnectorsGateway::add_connector(
				RuntimeOrigin::root(),
				external_address.clone(),
			));

			let expected_msg = MessageMock::First;
			let encoded_msg = expected_msg.serialize();

			let err = sp_runtime::DispatchError::from("connectors error");

			MockConnectors::mock_submit(move |mock_external_address, mock_msg| {
				assert_eq!(
					mock_external_address,
					DomainAddress::EVM(0, external_address.address)
				);
				assert_eq!(expected_msg, mock_msg);

				Err(err)
			});

			assert_noop!(
				ConnectorsGateway::process_msg(
					GatewayOrigin::Local(external_address).into(),
					BoundedVec::<u8, MaxIncomingMessageSize>::try_from(encoded_msg).unwrap()
				),
				err,
			);
		});
	}
}

mod outbound_queue_impl {
	use super::*;

	#[test]
	fn success() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let router = RouterMock::<Runtime>::default();
			router.mock_init(move || Ok(()));

			assert_ok!(ConnectorsGateway::set_domain_router(
				RuntimeOrigin::root(),
				domain.clone(),
				router.clone(),
			));

			let sender = get_test_account_id();
			let msg = MessageMock::First;

			router.mock_send({
				let sender = sender.clone();
				let msg = msg.clone();

				move |mock_sender, mock_msg| {
					assert_eq!(sender, mock_sender);
					assert_eq!(msg, mock_msg);

					Ok(())
				}
			});

			assert_ok!(ConnectorsGateway::submit(sender, domain, msg));
		});
	}

	#[test]
	fn router_error() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let router = RouterMock::<Runtime>::default();
			router.mock_init(move || Ok(()));

			assert_ok!(ConnectorsGateway::set_domain_router(
				RuntimeOrigin::root(),
				domain.clone(),
				router.clone(),
			));

			let sender = get_test_account_id();
			let msg = MessageMock::First;
			let expected_error = DispatchError::Other("router error");

			router.mock_send({
				let sender = sender.clone();
				let msg = msg.clone();

				move |mock_sender, mock_msg| {
					assert_eq!(sender, mock_sender);
					assert_eq!(msg, mock_msg);

					Err(expected_error)
				}
			});

			assert_noop!(
				ConnectorsGateway::submit(sender, domain, msg),
				expected_error,
			);
		});
	}

	#[test]
	fn router_not_found() {
		new_test_ext().execute_with(|| {
			let domain = 0;
			let sender = get_test_account_id();
			let msg = MessageMock::First;

			assert_noop!(
				ConnectorsGateway::submit(sender, domain, msg),
				Error::<Runtime>::RouterNotFound
			);
		});
	}
}
