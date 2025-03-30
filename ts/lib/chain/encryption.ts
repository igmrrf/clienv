const crypto = require("node:crypto");

const ALGORITHM = "aes-256-gcm";

function encrypt({ content, publicKey }) {
	const encryptionKey = crypto.randomBytes(16);
	const iv = crypto.randomBytes(12);

	const cipher = crypto.createCipheriv(
		ALGORITHM,
		Buffer.concat([encryptionKey, encryptionKey]),
		iv,
	);
	let encryptedContent = cipher.update(content, "utf8", "hex");
	encryptedContent += cipher.final("hex");
	const authTag = cipher.getAuthTag().toString("hex");

	const payload = {
		iv: iv.toString("hex"),
		content: encryptedContent,
		tag: authTag,
		key: encryptionKey.toString("hex"),
	};

	if (publicKey) {
		const encryptedKey = crypto
			.publicEncrypt(publicKey, encryptionKey)
			.toString("hex");
		payload.key = encryptedKey;
	}

	return payload;
}

function decrypt(payload) {
	const { iv, content, tag, key } = payload;

	const encryptionKey = Buffer.from(key, "hex");
	const fullKey = Buffer.concat([encryptionKey, encryptionKey]);
	const decipher = crypto.createDecipheriv(
		ALGORITHM,
		fullKey,
		Buffer.from(iv, "hex"),
	);
	decipher.setAuthTag(Buffer.from(tag, "hex"));
	let decryptedContent = decipher.update(content, "hex", "utf8");
	decryptedContent += decipher.final("utf8");

	return decryptedContent;
}

function generateKeyPair() {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: "spki",
			format: "pem",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "pem",
		},
	});

	return { publicKey, privateKey };
}

function rsaDecrypt(privateKey, content) {
	try {
		const decrypted = crypto.privateDecrypt(
			privateKey,
			Buffer.from(content, "hex"),
		);
		return decrypted.toString("hex");
	} catch (error) {
		throw new Error("Failed to view secret");
	}
}

function rsaSign(privateKey, content) {
	const signer = crypto.createSign("RSA-SHA256");
	signer.update(content);
	signer.end();
	return signer.sign(privateKey, "base64");
}

module.exports = {
	encrypt,
	decrypt,
	generateKeyPair,
	rsaDecrypt,
	rsaSign,
};
