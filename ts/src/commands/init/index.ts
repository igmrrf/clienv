import program from "../program";
import { generateKeyPair } from "../crypt";
import { getUserId, savePrivateKey, saveUserId } from "../wallet/helpers";

program
	.command("init")
	.argument("<user-id>", "A unique identifier for this machine")
	.description("Generate keys to receive secrets only readable on this machine")
	.action(async (userId) => {
		try {
			const existingUserId = getUserId();
			if (existingUserId) {
				console.log(`User already initialized with ID: ${existingUserId}`);
				process.exit(1);
			}

			const { publicKey, privateKey } = generateKeyPair();

			const response = await fetch(`${DEFAULT_RPC_URL}/init`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ userId, publicKey }),
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.error);
			}

			saveUserId(userId);
			savePrivateKey(privateKey);

			console.log(`Successfully initialized ${userId}`);
		} catch (error) {
			console.error(`Failed to initialize ${userId}:`, error);
			process.exit(1);
		}
	});
