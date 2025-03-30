import path from "node:path";
import { createAppDirIfNotExists, getAppDataDir } from "../../common/app";

export function getUserId() {
	const configPath = path.join(getAppDataDir(), "config.json");
	if (!fs.existsSync(configPath)) {
		return null;
	}

	const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
	return config.userId;
}

export function saveUserId(userId: string) {
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

export function savePrivateKey(privateKey: string) {
	createAppDirIfNotExists();
	const keyPath = path.join(getAppDataDir(), "key.pem");
	fs.writeFileSync(keyPath, privateKey, {
		mode: 0o600,
	});
}

export function getPrivateKey() {
	const keyPath = path.join(getAppDataDir(), "key.pem");
	if (!fs.existsSync(keyPath)) {
		return null;
	}
	return fs.readFileSync(keyPath, "utf8");
}
