var sourcesIndex = JSON.parse('{\
"altair_runtime":["",[["weights",[],["frame_system.rs","mod.rs","pallet_anchors.rs","pallet_balances.rs","pallet_block_rewards.rs","pallet_collator_allowlist.rs","pallet_collator_selection.rs","pallet_collective.rs","pallet_crowdloan_claim.rs","pallet_crowdloan_reward.rs","pallet_democracy.rs","pallet_fees.rs","pallet_identity.rs","pallet_interest_accrual.rs","pallet_keystore.rs","pallet_liquidity_rewards.rs","pallet_loans.rs","pallet_migration_manager.rs","pallet_multisig.rs","pallet_nft_sales.rs","pallet_order_book.rs","pallet_permissions.rs","pallet_pool_registry.rs","pallet_pool_system.rs","pallet_preimage.rs","pallet_proxy.rs","pallet_restricted_tokens.rs","pallet_scheduler.rs","pallet_session.rs","pallet_timestamp.rs","pallet_treasury.rs","pallet_uniques.rs","pallet_utility.rs","pallet_vesting.rs","pallet_xcm.rs"]]],["constants.rs","evm.rs","lib.rs","migrations.rs","xcm.rs"]],\
"axelar_gateway_precompile":["",[],["lib.rs","weights.rs"]],\
"centrifuge_chain":["",[["rpc",[],["anchors.rs","evm.rs","mod.rs","pools.rs","rewards.rs"]],["service",[],["evm.rs"]]],["chain_spec.rs","cli.rs","command.rs","main.rs","service.rs"]],\
"centrifuge_runtime":["",[["weights",[],["cumulus_pallet_xcmp_queue.rs","frame_system.rs","mod.rs","pallet_anchors.rs","pallet_balances.rs","pallet_block_rewards.rs","pallet_collator_allowlist.rs","pallet_collator_selection.rs","pallet_collective.rs","pallet_crowdloan_claim.rs","pallet_crowdloan_reward.rs","pallet_democracy.rs","pallet_elections_phragmen.rs","pallet_fees.rs","pallet_identity.rs","pallet_interest_accrual.rs","pallet_keystore.rs","pallet_liquidity_rewards.rs","pallet_loans.rs","pallet_migration_manager.rs","pallet_multisig.rs","pallet_order_book.rs","pallet_permissions.rs","pallet_pool_registry.rs","pallet_pool_system.rs","pallet_preimage.rs","pallet_proxy.rs","pallet_restricted_tokens.rs","pallet_scheduler.rs","pallet_session.rs","pallet_timestamp.rs","pallet_treasury.rs","pallet_uniques.rs","pallet_utility.rs","pallet_vesting.rs","pallet_xcm.rs"]]],["evm.rs","lib.rs","migrations.rs","xcm.rs"]],\
"cfg_mocks":["",[],["change_guard.rs","data.rs","fees.rs","lib.rs","liquidity_pools.rs","liquidity_pools_gateway_routers.rs","permissions.rs","pools.rs","rewards.rs","time.rs","try_convert.rs","write_off_policy.rs"]],\
"cfg_primitives":["",[],["conversion.rs","impls.rs","lib.rs"]],\
"cfg_test_utils":["",[["mocks",[],["accountant.rs","authority_origin.rs","mod.rs","nav.rs","order_manager.rs","orml_asset_registry.rs"]]],["lib.rs"]],\
"cfg_traits":["",[],["changes.rs","data.rs","ethereum.rs","interest.rs","investments.rs","lib.rs","liquidity_pools.rs","rewards.rs"]],\
"cfg_types":["",[],["adjustments.rs","consts.rs","domain_address.rs","epoch.rs","fee_keys.rs","fixed_point.rs","ids.rs","investments.rs","lib.rs","locations.rs","oracles.rs","orders.rs","permissions.rs","pools.rs","time.rs","tokens.rs","xcm.rs"]],\
"cfg_utils":["",[],["lib.rs"]],\
"development_runtime":["",[["weights",[],["cumulus_pallet_xcmp_queue.rs","frame_system.rs","mod.rs","pallet_anchors.rs","pallet_balances.rs","pallet_block_rewards.rs","pallet_collator_allowlist.rs","pallet_collator_selection.rs","pallet_collective.rs","pallet_crowdloan_claim.rs","pallet_crowdloan_reward.rs","pallet_democracy.rs","pallet_elections_phragmen.rs","pallet_fees.rs","pallet_identity.rs","pallet_interest_accrual.rs","pallet_keystore.rs","pallet_loans.rs","pallet_migration_manager.rs","pallet_multisig.rs","pallet_nft_sales.rs","pallet_order_book.rs","pallet_permissions.rs","pallet_pool_registry.rs","pallet_pool_system.rs","pallet_preimage.rs","pallet_proxy.rs","pallet_restricted_tokens.rs","pallet_scheduler.rs","pallet_session.rs","pallet_timestamp.rs","pallet_transfer_allowlist.rs","pallet_treasury.rs","pallet_uniques.rs","pallet_utility.rs","pallet_vesting.rs","pallet_xcm.rs"]]],["evm.rs","lib.rs","liquidity_pools.rs","xcm.rs"]],\
"liquidity_pools_gateway_routers":["",[["routers",[],["axelar_evm.rs","axelar_xcm.rs","ethereum_xcm.rs","mod.rs"]]],["lib.rs"]],\
"mock_builder":["",[],["lib.rs","location.rs","storage.rs","util.rs"]],\
"pallet_anchors":["",[],["common.rs","lib.rs","weights.rs"]],\
"pallet_block_rewards":["",[],["lib.rs","migrations.rs","weights.rs"]],\
"pallet_bridge":["",[],["lib.rs","weights.rs"]],\
"pallet_claims":["",[],["lib.rs","weights.rs"]],\
"pallet_collator_allowlist":["",[],["lib.rs","weights.rs"]],\
"pallet_crowdloan_claim":["",[],["lib.rs","weights.rs"]],\
"pallet_crowdloan_reward":["",[],["lib.rs","weights.rs"]],\
"pallet_data_collector":["",[],["lib.rs"]],\
"pallet_ethereum_transaction":["",[],["lib.rs"]],\
"pallet_fees":["",[],["lib.rs","weights.rs"]],\
"pallet_foreign_investments":["",[["impls",[],["invest.rs","mod.rs","redeem.rs"]]],["errors.rs","hooks.rs","lib.rs","types.rs"]],\
"pallet_interest_accrual":["",[],["lib.rs","weights.rs"]],\
"pallet_investments":["",[],["lib.rs","weights.rs"]],\
"pallet_keystore":["",[],["lib.rs","weights.rs"]],\
"pallet_liquidity_pools":["",[],["contract.rs","hooks.rs","inbound.rs","lib.rs","message.rs","routers.rs","weights.rs"]],\
"pallet_liquidity_pools_gateway":["",[],["lib.rs","origin.rs","weights.rs"]],\
"pallet_liquidity_rewards":["",[],["lib.rs","weights.rs"]],\
"pallet_loans":["",[["entities",[["pricing",[],["external.rs","internal.rs"]]],["interest.rs","loans.rs","pricing.rs"]],["types",[],["mod.rs","policy.rs","portfolio.rs","valuation.rs"]]],["lib.rs","util.rs","weights.rs"]],\
"pallet_migration_manager":["",[],["lib.rs","weights.rs"]],\
"pallet_nft":["",[],["lib.rs","types.rs","weights.rs"]],\
"pallet_nft_sales":["",[],["lib.rs","weights.rs"]],\
"pallet_order_book":["",[],["lib.rs","weights.rs"]],\
"pallet_permissions":["",[],["lib.rs","weights.rs"]],\
"pallet_pool_registry":["",[],["lib.rs","weights.rs"]],\
"pallet_pool_system":["",[],["impls.rs","lib.rs","pool_types.rs","solution.rs","tranches.rs","weights.rs"]],\
"pallet_restricted_tokens":["",[],["impl_currency.rs","impl_fungible.rs","impl_fungibles.rs","lib.rs","weights.rs"]],\
"pallet_rewards":["",[["mechanism",[],["base.rs","deferred.rs","gap.rs"]],["migrations",[],["new_instance.rs"]]],["issuance.rs","lib.rs","mechanism.rs"]],\
"pallet_transfer_allowlist":["",[],["lib.rs","weights.rs"]],\
"proofs":["",[],["lib.rs"]],\
"runtime_common":["",[["apis",[],["account_conversion.rs","anchors.rs","investments.rs","loans.rs","mod.rs","pools.rs","rewards.rs"]],["evm",[],["mod.rs","precompile.rs"]],["migrations",[],["asset_registry_xcmv3.rs","mod.rs","nuke.rs"]]],["account_conversion.rs","gateway.rs","lib.rs","oracle.rs","xcm.rs"]],\
"runtime_integration_tests":["",[],["lib.rs"]]\
}');
createSourceSidebar();
