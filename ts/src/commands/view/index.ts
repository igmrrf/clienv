import { decrypt, rsaDecrypt, rsaSign } from "../crypt";
import program from "../program";
import { getPrivateKey } from "../wallet/helpers";

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

			const response = await fetch(`${DEFAULT_RPC_URL}/retrieve/${id}`);
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

					const updateResponse = await fetch(`${DEFAULT_RPC_URL}/reads/${id}`, {
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
			console.error("Failed to retrieve secret:", error);
			process.exit(1);
		}
	});
