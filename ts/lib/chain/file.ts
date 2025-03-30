const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const isBinaryFile = require("isbinaryfile").isBinaryFileSync;

const packageJson = require("../package.json");

function readFileContent(filePath) {
	if (!fs.existsSync(filePath)) {
		console.error(`Error: File "${filePath}" does not exist.`);
		process.exit(1);
	}

	const isBinary = isBinaryFile(filePath);

	if (isBinary) {
		console.error(`Error: File "${filePath}" is not a valid text file.`);
		process.exit(1);
	}

	// Check if file is larger than 100KB
	const fileSize = fs.statSync(filePath).size;
	const maxSize = 100 * 1024; // 100KB in bytes

	if (fileSize > maxSize) {
		console.error(
			`Error: File "${filePath}" is too large. Maximum size is 100KB.`,
		);
		process.exit(1);
	}

	return fs.readFileSync(filePath, "utf8");
}

function getAppDataDir() {
	const homeDir = os.homedir();
	const appDir = path.join(homeDir, `.${packageJson.name}`);
	return appDir;
}

function createAppDirIfNotExists() {
	const appDir = getAppDataDir();
	if (!fs.existsSync(appDir)) {
		fs.mkdirSync(appDir, { recursive: true, mode: 0o700 });
	}
}

function getUserId() {
	const configPath = path.join(getAppDataDir(), "config.json");
	if (!fs.existsSync(configPath)) {
		return null;
	}

	const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
	return config.userId;
}

function saveUserId(userId) {
	createAppDirIfNotExists();
	const configPath = path.join(getAppDataDir(), "config.json");
	fs.writeFileSync(
		configPath,
		JSON.stringify({ userId, createdAt: Date.now() }),
		{
			mode: 0o600,
		},
	);
}

function savePrivateKey(privateKey) {
	createAppDirIfNotExists();
	const keyPath = path.join(getAppDataDir(), "key.pem");
	fs.writeFileSync(keyPath, privateKey, {
		mode: 0o600,
	});
}

function getPrivateKey() {
	const keyPath = path.join(getAppDataDir(), "key.pem");
	if (!fs.existsSync(keyPath)) {
		return null;
	}
	return fs.readFileSync(keyPath, "utf8");
}

module.exports = {
	readFileContent,
	getAppDataDir,
	getPrivateKey,
	savePrivateKey,
	getUserId,
	saveUserId,
};
