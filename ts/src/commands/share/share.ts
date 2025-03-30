import { encrypt } from "../crypt";
import program from "../program";
import ms from "ms";
import crypto from "node:crypto";

program
	.command("share [secret]")
	.description("Share a secret or a text file")
	.option("-f, --file <path>", "Path to a text file containing the secret")
	.option("-t, --ttl <ttl>", "Time-to-live (e.g. 1m, 2h, 1d)")
	.option("-u, --uid <user-id>", "Secret can only be read by this user")
	.option(
		"-l, --limit <count>",
		"Number of times the secret can be read",
		Number.parseInt,
	)
	.action(async (secret: string, options) => {
		if (!secret && !options.file) {
			console.error("Error: Provide a secret text or a file.");
			process.exit(1);
		}

		const DEFAULT_TTL = 60 * 60 * 24 * 7; // 7 days
		let ttl = DEFAULT_TTL;

		if (options.ttl) {
			const milliseconds = ms(options.ttl);

			if (!milliseconds) {
				console.error(
					"Error: Invalid TTL. Please provide a valid time duration (e.g. 1m, 2h, 1d)",
				);
				process.exit(1);
			}

			ttl = Number(milliseconds) / 1000;
			if (ttl < 60) {
				console.error("Error: Invalid TTL. TTL must be at least 1 minute");
				process.exit(1);
			}
		}

		let content = secret;

		if (options.file) {
			content = readFileContent(options.file);
		}

		const data: { content: string; publicKey?: string } = {
			content,
		};

		if (options.uid) {
			const publicKeyResponse = await fetch(
				`${DEFAULT_RPC_URL}/users/${options.uid}/key`,
			);
			if (!publicKeyResponse.ok) {
				console.error("Error: Invalid user id provided");
				process.exit(1);
			}

			const { publicKey } = await publicKeyResponse.json();
			data.publicKey = publicKey;
		}

		try {
			const encrypted = encrypt(data);

			const id = crypto.randomBytes(8).toString("hex");

			const payload = {
				id,
				content: encrypted.content,
				iv: encrypted.iv,
				tag: encrypted.tag,
				...(options.limit && { reads: options.limit }),
				...(options.ttl && { ttl }),
				...(options.uid && {
					uid: options.uid,
					encrypted: encrypted.key,
				}),
			};

			const response = await fetch(`${DEFAULT_RPC_URL}/store`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify(payload),
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.error);
			}

			let secretId = options.uid ? id : encrypted.key + id;

			secretId = Buffer.from(secretId, "hex").toString("base64url");

			console.log("\nTo view this secret, run:");
			console.log(`npx hidr view ${secretId}`);
		} catch (error) {
			console.error(`Failed to share secret: ${error}`);
			process.exit(1);
		}
	});
