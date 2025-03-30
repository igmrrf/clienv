import os from "node:os";
import path from "node:path";

export function getAppDataDir() {
	const homeDir = os.homedir();
	const appDir = path.join(homeDir, `.${packageJson.name}`);
	return appDir;
}

export function createAppDirIfNotExists() {
	const appDir = getAppDataDir();
	if (!fs.existsSync(appDir)) {
		fs.mkdirSync(appDir, { recursive: true, mode: 0o700 });
	}
}
