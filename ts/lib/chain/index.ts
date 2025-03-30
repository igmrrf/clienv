#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const { Command } = require("commander");
const ms = require("ms");
const packageJson = require("../../package.json");
const {
	readFileContent,
	getUserId,
	savePrivateKey,
	saveUserId,
	getPrivateKey,
} = require("./file");
const {
	encrypt,
	decrypt,
	generateKeyPair,
	rsaDecrypt,
	rsaSign,
} = require("./encryption");

const API_BASE_URL = process.env.API_BASE_URL;

const program = new Command();

program
	.name("secret-cli")
	.description("A CLI tool for securely sharing secrets")
	.version(packageJson.version);

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

			const response = await fetch(`${API_BASE_URL}/init`, {
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
			console.error(`Failed to initialize ${userId}`, error.message);
			process.exit(1);
		}
	});

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
	.action(async (secret, options) => {
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

			ttl = milliseconds / 1000;
			if (ttl < 60) {
				console.error("Error: Invalid TTL. TTL must be at least 1 minute");
				process.exit(1);
			}
		}

		let content = secret;

		if (options.file) {
			content = readFileContent(options.file);
		}

		const data = {
			content,
		};

		if (options.uid) {
			const publicKeyResponse = await fetch(
				`${API_BASE_URL}/users/${options.uid}/key`,
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

			const response = await fetch(`${API_BASE_URL}/store`, {
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
			console.error(`Failed to share secret: ${error.message}`);
			process.exit(1);
		}
	});

program
	.command("view <secret-id>")
	.description("Retrieve a shared secret")
	.option("-o, --output <file>", "Save output to a file")
	.action(async (secretId, options) => {
		try {
			const buffer = Buffer.from(secretId, "base64url");
			const hexString = buffer.toString("hex");

			let id = "";
			let key = "";

			if (hexString.length <= 16) {
				id = hexString;
			} else {
				key = hexString.slice(0, 32);
				id = hexString.slice(32);
			}

			const response = await fetch(`${API_BASE_URL}/retrieve/${id}`);
			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.error);
			}

			const data = await response.json();

			const decryptPayload = {
				content: data.content,
				iv: data.iv,
				tag: data.tag,
				key: key,
			};

			let privateKey = null;

			if (data.encrypted) {
				privateKey = getPrivateKey();
				if (!privateKey) {
					console.error(
						"Error: You do not have permission to view this secret",
					);
					process.exit(1);
				}

				const decryptedKey = rsaDecrypt(privateKey, data.encrypted);
				decryptPayload.key = decryptedKey;
			}

			const decryptedContent = decrypt(decryptPayload);

			if (options.output) {
				fs.writeFileSync(options.output, decryptedContent);
				console.log(`Successfully saved secret to: ${options.output}`);
			} else {
				console.log(decryptedContent);
			}

			if (data.remainingReads !== null) {
				if (data.encrypted) {
					const signature = rsaSign(privateKey, id);

					const updateResponse = await fetch(`${API_BASE_URL}/reads/${id}`, {
						method: "PUT",
						headers: {
							"Content-Type": "application/json",
							"X-Hidr-Signature": signature,
						},
					});

					if (updateResponse.ok) {
						console.log(`\nRemaining reads: ${data.remainingReads - 1}`);
					}
				} else {
					console.log(`\nRemaining reads: ${data.remainingReads}`);
				}
			}
		} catch (error) {
			console.error("Failed to retrieve secret:", error.message);
			process.exit(1);
		}
	});

program.parse(process.argv);
