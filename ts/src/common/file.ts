const isBinaryFile = require("isbinaryfile").isBinaryFileSync;

function readFileContent(filePath: string) {
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
