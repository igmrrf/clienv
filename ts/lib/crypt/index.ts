import crypto from "node:crypto";
import envfile from "envfile";
const writeFile = require("node:fs").writeFileSync;
const readFile = require("node:fs").readFileSync;
const exists = require("node:fs").existsSync;

const ENCRYPTION_ALGORITHM = "aes-256-ctr";
const HMAC_ALGORITHM = "sha256";
const AUTHENTICATION_KEY = "SENV_AUTHENTICATION";
const AUTHENTICATION_SALT = "SENV_SALT";

const PBKDF2_ITERATION_COUNT_FILE = 100000;
const PBKDF2_ITERATION_COUNT_STRING = 50000;

/**
 * Encrypts a string.
 * @param {string} string - The string to be encrypted.
 * @param {string} key - The password with which to encrypt the string.
 * @param {string} iv - The IV with which to encrypt the string.
 * @param {string=} name - the name of the variable
 */
export async function encryptString(string, key, iv, name?: string) {
	let encrypt_key = key;
	let encrypt_iv = iv;
	if (typeof key === "string") {
		encrypt_key = crypto.pbkdf2Sync(
			key,
			iv,
			PBKDF2_ITERATION_COUNT_STRING,
			32,
			"sha512",
		);
	}

	if (name) {
		encrypt_iv = Buffer.from(createHmac(iv, name).slice(0, 32), "hex");
	}

	const cipher = crypto.createCipheriv(
		ENCRYPTION_ALGORITHM,
		encrypt_key,
		encrypt_iv,
	);
	let encrypted = cipher.update(string, "utf8", "hex");
	encrypted += cipher.final("hex");

	return encrypted;
}

/**
 * Decrypts a string.
 * @param {string} string - The string to be decrypted.
 * @param {string} key - The password with which to decrypt the string.
 * @param {string} iv - The IV with which to encrypt the string.
 * @param {string=} name - the name of the variable
 */
export async function decryptString(string, key, iv, name?: string) {
	let encrypt_key = key;
	let encrypt_iv = iv;
	if (typeof key === "string") {
		encrypt_key = crypto.pbkdf2Sync(
			key,
			iv,
			PBKDF2_ITERATION_COUNT_STRING,
			32,
			"sha512",
		);
	}

	if (name) {
		encrypt_iv = Buffer.from(createHmac(iv, name).slice(0, 32), "hex");
	}

	const decipher = crypto.createDecipheriv(
		ENCRYPTION_ALGORITHM,
		encrypt_key,
		encrypt_iv,
	);
	let decrypted = decipher.update(string, "hex", "utf8");
	decrypted += decipher.final("utf8");

	return decrypted;
}

/**
 * Creates an HMAC from a string and password.
 * @param {string} string - The string to with which to create the HMAC.
 * @param {string} password - The password with which to create the HMAC.
 *
 * @returns {string}  - The created HMAC.
 */
export function createHmac(string, password) {
	const hmac = crypto.createHmac(HMAC_ALGORITHM, password);
	hmac.update(string);
	return hmac.digest("hex");
}

/**
 * Gets a password for decryption from various sources in order.
 * @param {string} fileName - The file name to convert
 * @returns {string}  - the corresponding password file name
 */
export function getPasswordFromEnvironment(fileName): string {
	// Get password for individual .env file from environment variable
	const individualPasswordEnvVarName = fileName
		.replace(".encrypted", "") // ignore encrypted filename part
		.replace(".enc", "") // ignore encrypted filename part
		.replace(".", "DOT") // replace first . with DOT
		.replace(/\./g, "_") // replace all other . with _
		.concat("_PASS")
		.toUpperCase();

	if (process.env[individualPasswordEnvVarName]) {
		return process.env[individualPasswordEnvVarName];
	}

	// Get password for individual .env file from password file
	const individualPasswordFileName = fileName
		.replace(".encrypted", "") // ignore encrypted filename part
		.replace(".enc", "") // ignore encrypted filename part
		.concat(".pass");

	if (exists(individualPasswordFileName)) {
		return readFile(individualPasswordFileName, "utf8");
	}

	// Get password for all .env files from environment variable
	const globalPasswordEnvVarName = "DOTENV_PASS";

	if (process.env[globalPasswordEnvVarName]) {
		return process.env[globalPasswordEnvVarName];
	}

	// Get password for all .env files from file
	const globalPasswordFileName = ".env.pass";

	if (exists(globalPasswordFileName)) {
		return readFile(globalPasswordFileName, "utf8");
	}

	// if no password found, throw error
	throw new Error("No password provided.");
}

/**
 * Encrypts a .env file and writes it to disk.
 * @param {string} inputFile    - File path to plain text .env file to encrypt.
 * @param {string} outputFile   - File path to write encrypted .env file to.
 * @param {string} password     - The password with which to encrypt the .env file.
 *
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
export async function encryptEnvFile(inputFile, outputFile, password?: string) {
	let decrypt_pass = password;
	if (!decrypt_pass) {
		decrypt_pass = getPasswordFromEnvironment(inputFile);
	}

	const envVariables = envfile.parseFileSync(inputFile);

	const salt = crypto.randomBytes(16);
	const key = crypto.pbkdf2Sync(
		decrypt_pass,
		salt,
		PBKDF2_ITERATION_COUNT_FILE,
		32,
		"sha512",
	);

	const hmac = createHmac(JSON.stringify(envVariables), key);

	// 32 because hex. (16 bytes)
	const iv = Buffer.from(hmac.slice(0, 32), "hex");

	for (const variableName in envVariables) {
		if (envVariables.hasOwnProperty(variableName)) {
			const value = envVariables[variableName];
			envVariables[variableName] = await encryptString(
				value,
				key,
				iv,
				variableName,
			);
		}
	}

	envVariables[AUTHENTICATION_KEY] = hmac;
	envVariables[AUTHENTICATION_SALT] = salt.toString("hex");

	const encryptedEnvVariables = envfile.stringifySync(envVariables);

	if (outputFile) {
		writeFile(outputFile, encryptedEnvVariables);
		return `Encrypted file successfully written to ${outputFile}`;
	}
	return encryptedEnvVariables;
}

/**
 * Decrypts a .env file and writes it to disk.
 * @param {string} inputFile    - Path to encrypted .env file to decrypt.
 * @param {string} outputFile   - Path to write decrypted .env file to.
 * @param {string} password     - The password with which to decrypt the .env file.
 *
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
export async function decryptEnvFile(inputFile, outputFile, password?: string) {
	let decrypt_pass = password;
	if (!decrypt_pass) {
		decrypt_pass = getPasswordFromEnvironment(inputFile);
	}

	const envVariables = envfile.parseFileSync(inputFile);
	const salt = Buffer.from(envVariables[AUTHENTICATION_SALT], "hex");
	const key = crypto.pbkdf2Sync(
		decrypt_pass,
		salt,
		PBKDF2_ITERATION_COUNT_FILE,
		32,
		"sha512",
	);

	const hmac = envVariables[AUTHENTICATION_KEY];

	// 32 because hex. (16 bytes)
	const iv = Buffer.from(hmac.slice(0, 32), "hex");

	delete envVariables[AUTHENTICATION_SALT];
	delete envVariables[AUTHENTICATION_KEY];

	for (const variableName in envVariables) {
		if (envVariables.hasOwnProperty(variableName)) {
			const encryptedValue = envVariables[variableName];
			envVariables[variableName] = await decryptString(
				encryptedValue,
				key,
				iv,
				variableName,
			);
		}
	}

	const calculatedHmac = createHmac(JSON.stringify(envVariables), key);

	if (hmac !== calculatedHmac) {
		throw new Error("Incorrect password provided.");
	}

	const decryptedEnvVariables = envfile.stringifySync(envVariables);

	if (outputFile) {
		writeFile(outputFile, decryptedEnvVariables);
		return `Decrypted file successfully written to ${outputFile}`;
	}
	return decryptedEnvVariables;
}
