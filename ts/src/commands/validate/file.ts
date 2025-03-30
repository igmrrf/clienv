import fs, { constants } from "node:fs";
import path from "node:path";
import appRoot from "app-root-path";
import chalk from "chalk";
import { prompt } from "inquirer";

import { getParsedAttributes } from "./helpers";
import { logEnvFileCreated, logInfo } from "./logger";
import {
	getCreateNewEnvFileQuestions,
	getUpdateEnvFileQuestions,
} from "./questions";

const { path: rootPath } = appRoot;

type Options = {
	skipCreateQuestion: boolean;
	skipUpdateQuestion: boolean;
};

const getFileFullPath = (file: string) => {
	const filePath =
		path.isAbsolute(file) && !file.startsWith(rootPath) ? rootPath : "";
	return path.join(filePath, file);
};

const writeFile = (file: string, text: string): Promise<void> =>
	new Promise((resolve, reject) => {
		const fullPath = getFileFullPath(file);
		// const fullPath = `${path.isAbsolute(file) ? '' : `${rootPath}/`}/${FILE}`
		const folderPath = fullPath.substring(0, fullPath.lastIndexOf("/"));
		try {
			fs.mkdir(folderPath, { recursive: true }, (err) => {
				if (err) reject(err);

				fs.writeFile(fullPath, text, (error) => {
					if (error) reject(error);
					else resolve();
				});
			});
		} catch (err) {
			reject(err);
		}
	});

export const createNewEnvFile = async (
	schemaContent: string,
	envFile: string,
	options: Options,
) => {
	if (options.skipCreateQuestion) {
		return writeFile(envFile, schemaContent).then(logEnvFileCreated(envFile));
	}

	const questions = getCreateNewEnvFileQuestions(envFile);
	const { createEnvFile } = await prompt(questions);

	if (createEnvFile)
		return writeFile(envFile, schemaContent).then(logEnvFileCreated(envFile));
};

export const updateEnvFile = async (
	options: Options,
	schemaContent: string,
	envContent: string,
	schemaFile: string,
	envFile: string,
) => {
	if (!options.skipUpdateQuestion) {
		const questions = getUpdateEnvFileQuestions(envFile, schemaFile);
		const { shouldUpdateEnvFile } = await prompt(questions);
		if (shouldUpdateEnvFile) {
			await processEnvFileToUpdate(
				schemaContent,
				envContent,
				schemaFile,
				envFile,
			);
			logInfo(
				`✅ Environment file (${chalk.underline(getShortFileName(envFile))}) updated successfully`,
			);
		}
		return;
	}

	/** If skipping asking for auto-update file */
	await processEnvFileToUpdate(schemaContent, envContent, schemaFile, envFile);
	logInfo(
		`✅ Environment file (${chalk.underline(getShortFileName(envFile))}) updated successfully`,
	);
};

// TODO: To be refactorized and simplified
const processEnvFileToUpdate = async (
	schemaContent: string,
	envContent: string,
	schemaFile: string,
	envFile: string,
) => {
	const schemaAttributes = getParsedAttributes(schemaContent);
	const envAttributes = getParsedAttributes(envContent);
	const keysNotInEnvFile = Object.keys(schemaAttributes).filter(
		(k) => !(k in envAttributes),
	);

	let finalContent = schemaContent;

	if (keysNotInEnvFile.length) {
		const textByLength =
			keysNotInEnvFile.length === 1
				? "Key which is going to be added:"
				: "Keys which are going to be added:";

		console.log(`
  ${chalk.underline(textByLength)}
   - ${chalk.bold(keysNotInEnvFile.join("\n   - "))}
    `);
	}

	const keysNotInSchemaFile = Object.keys(envAttributes).filter(
		(k) => !(k in schemaAttributes),
	);

	// If env file has other keys different than schema
	if (keysNotInSchemaFile.length) {
		const schemaFileName = schemaFile.split("/").slice(-1)[0];

		let envFileDifferentKeysBlock = `# **************** !!WARN!! KEYS NOT AVAILABLE IN ${schemaFileName} ****************\n`;

		const formattedKeysNotInSchemaFile = keysNotInSchemaFile
			.map((k) => `${k}=${envAttributes[k]}`)
			.join("\n  ");

		envFileDifferentKeysBlock += `  ${formattedKeysNotInSchemaFile}\n`;

		envFileDifferentKeysBlock += `# ${"*".repeat(schemaFileName.length + 65)}\n\n\n\n`;
		finalContent = envFileDifferentKeysBlock + finalContent;

		const textBylength =
			keysNotInSchemaFile.length === 1
				? `The following key is not present in the "${schemaFileName}" file:`
				: `The following keys are not present in the "${schemaFileName}" file:`;

		console.log(`
  ${chalk.bold.red("!! Alert !!")} ${chalk.underline(textBylength)}
               - ${chalk.bold(keysNotInSchemaFile.join("\n               - "))}
    `);
	}

	const finalContentByLines = finalContent.split("\n");

	finalContent = finalContentByLines
		.map((l) => {
			const lineAttributeObj = getParsedAttributes(l);
			const [key] = Object.keys(lineAttributeObj ?? {});

			// Ensure currentline is a config line
			if (key in envAttributes) {
				const equalsSymbolIdx = l.indexOf("=");
				const beforeEqualsContent = l.substring(
					0,
					equalsSymbolIdx >= 0 ? equalsSymbolIdx : undefined,
				);
				return `${beforeEqualsContent}=${envAttributes[key]}`;
			}
			return l;
		})
		.join("\n");

	return writeFile(envFile, finalContent);
};

export const readFile = (file: string): Promise<string> =>
	new Promise((resolve, reject) => {
		const fullPath = getFileFullPath(file);
		fs.readFile(fullPath, "utf8", (err, data) => {
			if (err) reject(err);
			else resolve(data);
		});
	});

export const fileExists = (file: string): Promise<boolean> =>
	new Promise((resolve, reject) => {
		const fullPath = getFileFullPath(file);
		fs.access(fullPath, constants.F_OK, (err) => {
			if (err) {
				reject(err);
			}
			resolve(true);
		});
	});

export const getShortFileName = (filePath: string) =>
	filePath.split("/").slice(-1)[0];
