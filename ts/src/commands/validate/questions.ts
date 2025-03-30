export function getShortFileName(filePath: string) {
	return filePath.split("/").slice(-1)[0];
}

export const getCreateNewEnvFileQuestions = (envFile: string) => {
	const envFileName = getShortFileName(envFile);
	return {
		type: "confirm",
		name: "createEnvFile",
		message: ` We have seen that the "${envFileName}" file is not created. \nDo you want to continue creating the file?`,
		default: true,
	};
};

export const getUpdateEnvFileQuestions = (
	envFile: string,
	schemaFile: string,
) => {
	const envFileName = getShortFileName(envFile);
	const schemaFileName = getShortFileName(schemaFile);
	return {
		type: "confirm",
		name: "shouldUpdateEnvFile",
		message: ` We have seen that the "${envFileName}" file differs from the "${schemaFileName}" file. \nDo you want to continue updating the file?`,
		default: true,
	};
};
