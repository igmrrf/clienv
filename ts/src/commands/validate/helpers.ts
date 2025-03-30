export const getParsedAttributes = (fileContent: string) => {
	const lines = fileContent.split("\n");
	return lines.reduce((acc: { [key: string]: string }, curr) => {
		const line = curr.trim();

		// If it's not a comment line
		if (!line.startsWith("#")) {
			const equalsSymbolIdx = line.indexOf("=");
			const key = line.substring(
				0,
				equalsSymbolIdx >= 0 ? equalsSymbolIdx : undefined,
			);
			const value =
				equalsSymbolIdx !== -1 ? line.substring(equalsSymbolIdx + 1) : "";

			if (key) acc[key] = value ?? "";
		}

		return acc;
	}, {});
};

export const areAttributesDifferent = (
	schemaContent: string,
	envContent: string,
) => {
	const schemaAttributes = Object.keys(
		getParsedAttributes(schemaContent) ?? {},
	);
	const envAttributes = Object.keys(getParsedAttributes(envContent) ?? {});
	return JSON.stringify(schemaAttributes) !== JSON.stringify(envAttributes);
};
