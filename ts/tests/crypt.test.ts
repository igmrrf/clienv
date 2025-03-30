import crypto from "node:crypto";
import {
	decryptEnvFile,
	decryptString,
	encryptEnvFile,
	encryptString,
	getPasswordFromEnvironment,
} from "../lib/crypt";

const writeFile = require("node:fs").writeFileSync;
const remove = require("node:fs").unlinkSync;
const exists = require("node:fs").existsSync;

const TMPDIR = process.env.TMPDIR;

const EXAMPLE_ENV_FILE = `
ENV_VAR=123
ENV_VAR_2=abc
`.trim();

test("encrypts/decrypts string successfully", async () => {
	const testString = "Hello world!";
	const testPassword = "password";
	const iv = crypto.randomBytes(16);
	const encryptedString = await encryptString(testString, testPassword, iv);

	expect(encryptedString).not.toBe(testString);
	expect(encryptedString).not.toBeNull();

	expect(await decryptString(encryptedString, testPassword, iv)).toBe(
		testString,
	);
});

test("gets individual .env file password from env var", async () => {
	const password = "password";
	process.env.DOTENV_PROD_PASS = password;

	expect(getPasswordFromEnvironment(".env.prod")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.encrypted")).toBe(password);

	process.env.DOTENV_PROD_PASS = undefined;
});

test("gets individual .env file password from password file", async () => {
	const password = "password";
	const path = ".env.prod.pass";
	writeFile(path, password);

	expect(getPasswordFromEnvironment(".env.prod")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.encrypted")).toBe(password);

	remove(path);
});

test("gets global .env file password from env var", async () => {
	const password = "password";
	process.env.DOTENV_PASS = password;

	expect(getPasswordFromEnvironment(".env.prod")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.encrypted")).toBe(password);

	process.env.DOTENV_PASS = undefined;
});

test("gets global .env file password from password file", async () => {
	const password = "password";
	const path = ".env.pass";
	writeFile(path, password);

	expect(getPasswordFromEnvironment(".env.prod")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
	expect(getPasswordFromEnvironment(".env.prod.encrypted")).toBe(password);

	remove(path);
});

test("encrypting env file fails without password", () => {
	expect(encryptEnvFile("path", undefined)).rejects.toThrow("password");
	expect(encryptEnvFile("path", null)).rejects.toThrow("password");
	expect(encryptEnvFile("path", "")).rejects.toThrow("password");
});

test("decrypting env file fails without password", () => {
	expect(decryptEnvFile("path", undefined)).rejects.toThrow("password");
	expect(decryptEnvFile("path", null)).rejects.toThrow("password");
	expect(decryptEnvFile("path", "")).rejects.toThrow("password");
});

test("encrypted env file is written successfully", async () => {
	const path = `${TMPDIR}.env.test1`;
	const encryptedEnvPath = `${TMPDIR}.env.enc.test1`;

	writeFile(path, EXAMPLE_ENV_FILE);

	await encryptEnvFile(path, encryptedEnvPath, "password");

	expect(exists(encryptedEnvPath)).toBeTruthy();

	remove(path);
	remove(encryptedEnvPath);
});

test("encrypted env file has correct variables", async () => {
	const path = `${TMPDIR}.env.test1`;
	writeFile(path, EXAMPLE_ENV_FILE);

	const encryptedEnvFile = await encryptEnvFile(path, null, "password");

	expect(encryptedEnvFile).toContain("ENV_VAR");
	expect(encryptedEnvFile).toContain("ENV_VAR_2");

	remove(path);
});

test("encrypted env file variable values have changed", async () => {
	const path = `${TMPDIR}.env.test2`;
	writeFile(path, EXAMPLE_ENV_FILE);

	const encryptedEnvFile = await encryptEnvFile(path, null, "password");

	expect(encryptedEnvFile).not.toEqual(EXAMPLE_ENV_FILE);

	remove(path);
});

test("decrypted env file is written successfully", async () => {
	const path = `${TMPDIR}.env.test1`;
	const encryptedEnvPath = `${TMPDIR}.env.enc.test1`;

	writeFile(path, EXAMPLE_ENV_FILE);

	await encryptEnvFile(path, encryptedEnvPath, "password");
	remove(path);

	await decryptEnvFile(encryptedEnvPath, path, "password");
	expect(exists(path)).toBeTruthy();

	remove(encryptedEnvPath);
});

test("decrypted env file has correct variables", async () => {
	const envVarPath = `${TMPDIR}.env.test3`;
	const encryptedEnvVarPath = `${TMPDIR}.env.enc.test3`;
	writeFile(envVarPath, EXAMPLE_ENV_FILE);

	await encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
	const decryptedEnvFile = await decryptEnvFile(
		encryptedEnvVarPath,
		null,
		"password",
	);

	expect(decryptedEnvFile.trim()).toContain("ENV_VAR");
	expect(decryptedEnvFile.trim()).toContain("ENV_VAR_2");

	remove(envVarPath);
	remove(encryptedEnvVarPath);
});

test("decrypted env file variables are correct", async () => {
	const envVarPath = `${TMPDIR}.env.test4`;
	const encryptedEnvVarPath = `${TMPDIR}.env.enc.test4`;
	writeFile(envVarPath, EXAMPLE_ENV_FILE);

	await encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
	const decryptedEnvFile = await decryptEnvFile(
		encryptedEnvVarPath,
		null,
		"password",
	);

	expect(decryptedEnvFile.trim()).toEqual(EXAMPLE_ENV_FILE.trim());

	remove(envVarPath);
	remove(encryptedEnvVarPath);
});

test("decrypting env throws error when password is incorrect", async () => {
	const envVarPath = `${TMPDIR}.env.test4`;
	const encryptedEnvVarPath = `${TMPDIR}.env.enc.test4`;
	writeFile(envVarPath, EXAMPLE_ENV_FILE);

	await encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
	expect(
		decryptEnvFile(encryptedEnvVarPath, null, "wrongpassword"),
	).rejects.toThrow("Incorrect password");

	remove(envVarPath);
	remove(encryptedEnvVarPath);
});
