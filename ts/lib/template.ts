const fs = require("node:fs");

fs.readFile(".env", "utf8", (err, data) => {
	if (err) {
		throw err;
	}
	const tempData = [];
	let tempEnv = "";
	const splited = data.split("\n");
	for (const element of splited) {
		const key = element.split("=")[0];
		if (key.length !== 0) {
			tempData.push(key.concat(`=#Your ${key} here\n`));
		}
	}
	for (const element of tempData) {
		tempEnv = `${tempEnv}${element}`;
	}

	fs.writeFile(".env.template", tempEnv, (err) => {
		if (err) throw err;
		console.log(".env.template file created successfully");
	});
});
