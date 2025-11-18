use std::str::FromStr;

use starknet::core::types::{BlockId, ConfirmedBlockId, MaybePreConfirmedStateUpdate};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, ProviderError, Url};
use starknet_api::block::BlockNumber;
use starknet_api::state::StateUpdate;
use starknet_api::{contract_address, contract_class};
use starknet_core::types::ContractStorageKeys;
use starknet_types_core::felt::{self, Felt};

#[tokio::main]
async fn main() {
    let orginal_http_transport =
        HttpTransport::new(Url::from_str("http://localhost:5050").unwrap());
    let forked_http_transport = HttpTransport::new(Url::from_str("http://localhost:5051").unwrap());

    let orginal_client = JsonRpcClient::new(orginal_http_transport);
    let forked_client = JsonRpcClient::new(forked_http_transport);

    check_storage_proof(&orginal_client, &forked_client).await;
    // check_trace(&orginal_client, &forked_client).await;
    // check_nonce(&orginal_client, &forked_client).await;
    // check_class(&orginal_client, &forked_client).await;
    // check_class_at(&orginal_client, &forked_client).await;
    // check_state_update(&orginal_client, &forked_client).await;
    // check_storage_at(&orginal_client, &forked_client).await;
}

pub async fn check_storage_proof(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let forked_storage_proof = client
        .get_storage_proof(
            ConfirmedBlockId::Number(0),
            vec![],
            [Felt::from_hex_unchecked(
                "0x123",
            )],
            [ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked(
                    "0x4382ec97da6637a0c6da3974a3f08904efb4548b20b7e7291afe7b5f68c1027",
                ),
                storage_keys: vec![Felt::from_hex_unchecked(
                    "0x1704e5494cfadd87ce405d38a662ae6a1d354612ea0ebdc9fefdeb969065774",
                )],
            }],
        )
        .await
        .unwrap();
    println!("{:#?}", forked_storage_proof);
    let forked_storage_proof = forked_client
        .get_storage_proof(
            ConfirmedBlockId::Number(0),
            vec![],
            [Felt::from_hex_unchecked(
                "0x123",
            )],
            [ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked(
                    "0x4382ec97da6637a0c6da3974a3f08904efb4548b20b7e7291afe7b5f68c1027",
                ),
                storage_keys: vec![Felt::from_hex_unchecked(
                    "0x1704e5494cfadd87ce405d38a662ae6a1d354612ea0ebdc9fefdeb969065774",
                )],
            }],
        )
        .await
        .unwrap();

    // assert!(storage_proof == forked_storage_proof);
}
pub async fn check_trace(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let trace = client
        .trace_block_transactions(ConfirmedBlockId::Number(9))
        .await
        .unwrap();
    let forked_trace = forked_client
        .trace_block_transactions(ConfirmedBlockId::Number(9))
        .await
        .unwrap();
    assert!(trace == forked_trace);
}

pub async fn check_nonce(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let nonce = client
        .get_nonce(
            BlockId::Number(8),
            Felt::from_hex("0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d")
                .unwrap(),
        )
        .await
        .unwrap();
    let forked_nonce = forked_client
        .get_nonce(
            BlockId::Number(8),
            Felt::from_hex("0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d")
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        nonce == forked_nonce,
        "original nonce: {:?}, forked nonce: {:?}",
        nonce,
        forked_nonce
    );
}

pub async fn check_class(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    // let contract_class = client
    //     .get_class(
    //         BlockId::Number(9),
    //         Felt::from_hex("0x2dca898b48c80c247ce2e74e7230f3e568224f5074441a659259cf4dea550d4")
    //             .unwrap(),
    //     )
    //     .await
    //     .unwrap();
    // let forked_contract_class = forked_client
    //     .get_class(
    //         BlockId::Number(9),
    //         Felt::from_hex("0x2dca898b48c80c247ce2e74e7230f3e568224f5074441a659259cf4dea550d4")
    //             .unwrap(),
    //     )
    //     .await
    //     .unwrap();
    // assert!(
    //     contract_class == forked_contract_class,
    //     "original class: {:?}, forked class: {:?}",
    //     contract_class,
    //     forked_contract_class
    // );

    let c = client
        .get_class(
            BlockId::Number(0),
            Felt::from_hex_unchecked(
                "0x57994b6a75fad550ca18b41ee82e2110e158c59028c4478109a67965a0e5b1e",
            ),
        )
        .await;
    let fork_c = forked_client
        .get_class(
            BlockId::Number(0),
            Felt::from_hex_unchecked(
                "0x57994b6a75fad550ca18b41ee82e2110e158c59028c4478109a67965a0e5b1e",
            ),
        )
        .await;
    assert!(
        c.is_err() && fork_c.is_err(),
        "Expected error for non existing class hash"
    );
    let expected = starknet::core::types::StarknetError::ClassHashNotFound;
    let Err(err) = c else {
        panic!("Expected error, got {:?}", c);
    };
    let err = match err {
        ProviderError::StarknetError(starknet::core::types::StarknetError::ClassHashNotFound) => {
            starknet::core::types::StarknetError::ClassHashNotFound
        }
        _ => panic!("Expected ClassHashNotFound error, got {:?}", err),
    };
    assert!(err == expected, "Expected {:?}, got {:?}", expected, err);
}

pub async fn check_class_at(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let contract_class = client
        .get_class_at(
            BlockId::Number(9),
            **contract_address!(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d"
            ),
        )
        .await
        .unwrap();
    let forked_contract_class = forked_client
        .get_class_at(
            BlockId::Number(9),
            **contract_address!(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d"
            ),
        )
        .await
        .unwrap();

    assert!(
        contract_class == forked_contract_class,
        "original class at: {:?}, forked class at: {:?}",
        contract_class,
        forked_contract_class
    );
}

pub async fn check_state_update(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let state_update = client.get_state_update(BlockId::Number(9)).await.unwrap();
    let x = match state_update.clone() {
        MaybePreConfirmedStateUpdate::Update(update) => update,
        MaybePreConfirmedStateUpdate::PreConfirmedUpdate(_) => {
            panic!("Expected StateUpdate, got PreConfirmedStateUpdate")
        }
    };
    println!("{:#?}", x.state_diff.storage_diffs);

    let forked_state_update = forked_client
        .get_state_update(BlockId::Number(9))
        .await
        .unwrap();
    assert!(state_update == forked_state_update);
}

pub async fn check_storage_at(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let storage_value = client
        .get_storage_at(
            Felt::from_hex("0x2").unwrap(),
            Felt::from_hex("0x0").unwrap(),
            BlockId::Number(9),
        )
        .await
        .unwrap();

    let forked_storage_value = forked_client
        .get_storage_at(
            Felt::from_hex("0x2").unwrap(),
            Felt::from_hex("0x0").unwrap(),
            BlockId::Number(9),
        )
        .await
        .unwrap();
    assert!(
        storage_value == forked_storage_value,
        "original storage value: {:?}, forked storage value: {:?}",
        storage_value,
        forked_storage_value
    );
}
