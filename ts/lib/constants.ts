const SUPPORTED_NETWORKS = {
	near: {
		name: "NEAR Protocol",
		rpcUrl: "https://rpc.mainnet.near.org",
		contractPlatform: "rust",
		fees: "zero",
		storageModel: "pay-per-byte",
	},
	solana: {
		name: "Solana",
		rpcUrl: "https://api.mainnet-beta.solana.com",
		contractPlatform: "rust",
		fees: "near-zero",
		storageModel: "account-based",
	},
	iota: {
		name: "IOTA",
		rpcUrl: "https://nodes.iota.org",
		contractPlatform: "rust-wasm",
		fees: "zero",
		storageModel: "data-transaction",
	},
	stellar: {
		name: "Stellar",
		rpcUrl: "https://horizon.stellar.org",
		contractPlatform: "stellar-smart-contracts",
		fees: "near-zero",
		storageModel: "ledger-entry",
	},
};

const DEFAULT_NETWORK = "near";
