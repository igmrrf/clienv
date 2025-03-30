program
	.command("network")
	.description("Configure blockchain network")
	.option("-n, --name <network>", "Network name (near, solana, iota, stellar)")
	.option("--rpc <url>", "Custom RPC endpoint")
	.option("--contract <address>", "Custom contract address")
	.action(async (options) => {
		if (!SUPPORTED_NETWORKS[options.name]) {
			console.error("Unsupported network. Available networks:");
			for (const net of SUPPORTED_NETWORKS) {
				console.log(`- ${net} (${SUPPORTED_NETWORKS[net].name})`);
			}
			process.exit(1);
		}

		// Network-specific initialization
		switch (options.name) {
			case "near":
				await initNearNetwork(options);
				break;
			case "solana":
				await initSolanaNetwork(options);
				break;
			case "iota":
				await initIotaNetwork(options);
				break;
			case "stellar":
				await initStellarNetwork(options);
				break;
		}
	});
