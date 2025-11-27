use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
use starknet_core::types::{BlockId, ConfirmedBlockId, ContractStorageKeys, Felt};
use std::vec;

pub async fn check_chain_id(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let chain_id = client.chain_id().await.unwrap();
    let forked_chain_id = forked_client.chain_id().await.unwrap();
    assert_eq!(chain_id, forked_chain_id);
}

pub async fn check_get_block_with_txs(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let block_with_txs = client.get_block_with_txs(BlockId::Number(5)).await.unwrap();
    let forked_block_with_txs = forked_client
        .get_block_with_txs(BlockId::Number(5))
        .await
        .unwrap();
    assert_eq!(block_with_txs, forked_block_with_txs);
}

pub async fn check_get_block_with_tx_hashes(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let blocks = vec![0u64, 4u64];
    for block_number in blocks {
        let block_with_tx_hashes = client
            .get_block_with_tx_hashes(BlockId::Number(block_number))
            .await
            .unwrap();
        let forked_block_with_tx_hashes = forked_client
            .get_block_with_tx_hashes(BlockId::Number(block_number))
            .await
            .unwrap();
        assert_eq!(block_with_tx_hashes, forked_block_with_tx_hashes);
    }
}

pub async fn check_trace_block_transactions(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let trace = client
        .trace_block_transactions(ConfirmedBlockId::Number(5))
        .await
        .unwrap();
    let forked_trace = forked_client
        .trace_block_transactions(ConfirmedBlockId::Number(5))
        .await
        .unwrap();
    assert_eq!(trace, forked_trace);
}

pub async fn check_get_state_update(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let state_update = client.get_state_update(BlockId::Number(5)).await.unwrap();
    let forked_state_update = forked_client
        .get_state_update(BlockId::Number(5))
        .await
        .unwrap();
    assert_eq!(state_update, forked_state_update);
}

pub async fn get_class(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let get_class_cases = vec![
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x6d3d9a8a689da03f37a9115a732f8fd52550f16c55b6f025ea6d5babc9696ea",
            ),
        ),
        (
            5u64,
            Felt::from_hex_unchecked(
                "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2",
            ),
        ),
        (
            5u64,
            Felt::from_hex_unchecked(
                "0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac",
            ),
        ),
        (
            5u64,
            Felt::from_hex_unchecked(
                "0x6d3d9a8a689da03f37a9115a732f8fd52550f16c55b6f025ea6d5babc9696ea",
            ),
        ),
    ];
    for (block_number, class_hash) in get_class_cases {
        let class = client
            .get_class(BlockId::Number(block_number), class_hash)
            .await;
        let forked_class = forked_client
            .get_class(BlockId::Number(block_number), class_hash)
            .await;
        match (class, forked_class) {
            (Ok(a), Ok(b)) => {
                assert!(
                    a == b,
                    "{}",
                    format!(
                        "no match for block number: {}, class hash: 0x{:x}",
                        block_number, class_hash
                    )
                )
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(format!("{}", e1), format!("{}", e2));
            }
            _ => panic!("Mismatch between original and forked get_class results"),
        }
    }
}

pub async fn check_get_storage_at(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let get_storage_at_cases = vec![
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            Felt::from_hex_unchecked(
                "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            Felt::from_hex_unchecked(
                "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850071",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            Felt::from_hex_unchecked(
                "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            Felt::from_hex_unchecked(
                "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f0a",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x1"),
            Felt::from_hex_unchecked("0x0"),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f0a",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850071",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked("0x0"),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x6d3d9a8a689da03f37a9115a732f8fd52550f16c55b6f025ea6d5babc9696ea",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
            ),
            Felt::from_hex_unchecked(
                "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
            ),
        ),
    ];
    for (block_number, contract_address, key) in get_storage_at_cases {
        let storage_value = client
            .get_storage_at(contract_address, key, BlockId::Number(block_number))
            .await;
        let forked_storage_value = forked_client
            .get_storage_at(contract_address, key, BlockId::Number(block_number))
            .await;
        match (storage_value, forked_storage_value) {
            (Ok(a), Ok(b)) => {
                assert!(
                    a == b,
                    "{}",
                    format!(
                        "no match for block number: {}, contract address: 0x{:x}, key: 0x{:x}",
                        block_number, contract_address, key
                    )
                )
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(format!("{}", e1), format!("{}", e2));
            }
            _ => panic!("Mismatch between original and forked get_storage_at results"),
        }
    }
}

pub async fn check_get_class_hash_at(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let get_class_hash_at_cases = vec![
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
            ),
        ),
        (
            4u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
        ),
        (
            5u64,
            Felt::from_hex_unchecked(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
            ),
        ),
        (
            5u64,
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
        ),
    ];
    for (block_number, contract_address) in get_class_hash_at_cases {
        let class_hash = client
            .get_class_hash_at(BlockId::Number(block_number), contract_address)
            .await;
        let forked_class_hash = forked_client
            .get_class_hash_at(BlockId::Number(block_number), contract_address)
            .await;
        match (class_hash, forked_class_hash) {
            (Ok(a), Ok(b)) => {
                assert!(
                    a == b,
                    "{}",
                    format!(
                        "no match for block number: {}, contract address: 0x{:x}",
                        block_number, contract_address
                    )
                )
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(format!("{}", e1), format!("{}", e2));
            }
            _ => panic!("Mismatch between original and forked get_class_hash_at results"),
        }
    }
}

pub async fn get_nonce(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let block_id = BlockId::Number(4u64);
    let contract_adresses = vec![
        "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
        "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
        "0x2",
        "0x1",
    ]
    .iter()
    .map(|s| Felt::from_hex_unchecked(s))
    .collect::<Vec<Felt>>();
    for address in contract_adresses {
        let nonce: Result<Felt, starknet::providers::ProviderError> =
            client.get_nonce(block_id.clone(), address).await;
        let forked_nonce: Result<Felt, starknet::providers::ProviderError> =
            forked_client.get_nonce(block_id.clone(), address).await;
        match (nonce, forked_nonce) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(e1), Err(e2)) => {
                assert_eq!(format!("{}", e1), format!("{}", e2));
            }
            _ => panic!("Mismatch between original and forked nonce results"),
        }
    }
}

pub async fn check_storage_proof(
    client: &JsonRpcClient<HttpTransport>,
    forked_client: &JsonRpcClient<HttpTransport>,
) {
    let class_hash = vec![
        Felt::from_hex_unchecked(
            "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2",
        ),
        Felt::from_hex_unchecked(
            "0x6d3d9a8a689da03f37a9115a732f8fd52550f16c55b6f025ea6d5babc9696ea",
        ),
    ];
    let contracts_storage_keys = vec![
        (
            Felt::from_hex_unchecked("0x1"),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked("0x1"),
                storage_keys: vec!["0x0"]
                    .iter()
                    .map(|s| Felt::from_hex_unchecked(s))
                    .collect(),
            },
        ),
        (
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked(
                    "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
                ),
                storage_keys: vec![
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f0a",
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850071",
                ]
                .iter()
                .map(|s| Felt::from_hex_unchecked(s))
                .collect(),
            },
        ),
        (
            Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked(
                    "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
                ),
                storage_keys: vec![
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
                ]
                .iter()
                .map(|s| Felt::from_hex_unchecked(s))
                .collect(),
            },
        ),
        (
            Felt::from_hex_unchecked("0x2"),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked("0x2"),
                storage_keys: vec![
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f0a",
                    "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
                    "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850071",
                    "0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac",
                    "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
                    "0x0",
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
                    "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2",
                    "0x6d3d9a8a689da03f37a9115a732f8fd52550f16c55b6f025ea6d5babc9696ea",
                ]
                .iter()
                .map(|s| Felt::from_hex_unchecked(s))
                .collect(),
            },
        ),
        (
            Felt::from_hex_unchecked("0x2"),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked("0x2"),
                storage_keys: vec![
                    "0x7b62949c85c6af8a50c11c22927f9302f7a2e40bc93b4c988415915b0f97f09",
                    "0x67840c21d0d3cba9ed504d8867dffe868f3d43708cfc0d7ed7980b511850070",
                    "0xb6ce5410fca59d078ee9b2a4371a9d684c530d697c64fbef0ae6d5e8f0ac72",
                    "0x7dd7240cedfebc99e07b3fc062abd0c5c51fbb2745835dd8599ff588148933a",
                    "0x6e89277485f30e1e6c84db4f68e94c1e08265aaada9f912de56b129e1a9beb2",
                ]
                .iter()
                .map(|s| Felt::from_hex_unchecked(s))
                .collect(),
            },
        ),
        (
            Felt::from_hex_unchecked(
                "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
            ),
            ContractStorageKeys {
                contract_address: Felt::from_hex_unchecked(
                    "0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
                ),
                storage_keys: vec![
                    "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
                ]
                .iter()
                .map(|s| Felt::from_hex_unchecked(s))
                .collect(),
            },
        ),
    ];
    let block_numbers = vec![4u64, 5u64];
    for hash in class_hash {
        for block_number in &block_numbers {
            let storage_proof = client
                .get_storage_proof(ConfirmedBlockId::Number(*block_number), vec![], [hash], [])
                .await
                .unwrap();
            let forked_storage_proof = forked_client
                .get_storage_proof(ConfirmedBlockId::Number(*block_number), vec![], [hash], [])
                .await
                .unwrap();
            assert!(
                storage_proof == forked_storage_proof,
                "Storage proof mismatch for class hash: {}",
                hash
            );
        }
    }
    for (address, storage_keys) in contracts_storage_keys {
        for block_number in &block_numbers {
            let storage_proof = client
                .get_storage_proof(
                    ConfirmedBlockId::Number(*block_number),
                    vec![],
                    [address],
                    [storage_keys.clone()],
                )
                .await
                .unwrap();
            let forked_storage_proof = forked_client
                .get_storage_proof(
                    ConfirmedBlockId::Number(*block_number),
                    vec![],
                    [address],
                    [storage_keys.clone()],
                )
                .await
                .unwrap();
            assert!(
                storage_proof == forked_storage_proof,
                "Storage proof mismatch for contract address: {}",
                address
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Url};

    use super::*;

    fn get_clients() -> (JsonRpcClient<HttpTransport>, JsonRpcClient<HttpTransport>) {
        let orginal_http_transport =
            HttpTransport::new(Url::from_str("http://localhost:5050").unwrap());
        let forked_http_transport =
            HttpTransport::new(Url::from_str("http://localhost:5051").unwrap());
        let orginal_client = JsonRpcClient::new(orginal_http_transport);
        let forked_client = JsonRpcClient::new(forked_http_transport);
        (orginal_client, forked_client)
    }

    #[tokio::test]
    async fn test_check_chain_id() {
        let (orginal_client, forked_client) = get_clients();
        check_chain_id(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_get_block_with_txs() {
        let (orginal_client, forked_client) = get_clients();
        check_get_block_with_txs(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_get_block_with_tx_hashes() {
        let (orginal_client, forked_client) = get_clients();
        check_get_block_with_tx_hashes(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_trace_block_transactions() {
        let (orginal_client, forked_client) = get_clients();
        check_trace_block_transactions(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_get_state_update() {
        let (orginal_client, forked_client) = get_clients();
        check_get_state_update(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_get_class() {
        let (orginal_client, forked_client) = get_clients();
        get_class(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_get_storage_at() {
        let (orginal_client, forked_client) = get_clients();
        check_get_storage_at(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_get_class_hash_at() {
        let (orginal_client, forked_client) = get_clients();
        check_get_class_hash_at(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_get_nonce() {
        let (orginal_client, forked_client) = get_clients();
        get_nonce(&orginal_client, &forked_client).await;
    }

    #[tokio::test]
    async fn test_check_storage_proof() {
        let (orginal_client, forked_client) = get_clients();
        check_storage_proof(&orginal_client, &forked_client).await;
    }
}
