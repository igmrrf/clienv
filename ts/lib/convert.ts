const fs = require("node:fs");
const convert = () => {
	const input_file = args.file;

	if (!input_file) {
		console.log("invalid usage, Try `clienv convert --help` for help.");
		return;
	}

	const input_file_ext = input_file.split(".").slice(-1)[0];
	const input_file_stem = input_file.split(".").slice(0, -1).join();
	const prefix = args.prefix ? args.prefix : "";
	const suffix = args.suffix ? args.suffix : "";
	const output_file = args.out ? args.out : `${input_file_stem}.env`;

	if (input_file_ext !== "json") {
		console.log("the file is not *.json. try `clienv convert --help` for help");
	}

	const rawdata = fs.readFileSync(input_file);
	const data = JSON.parse(rawdata);

	if (args.embed) {
		const embed = Object.keys(data)
			.map((key) => `${key}: ${prefix}${key}${suffix}`)
			.join(",\n");
		console.log(`{
  ${embed}
}`);
	} else {
		const envdata = Object.keys(data)
			.map((key) => `${prefix}${key}${suffix}='${data[key]}'`)
			.join("\n");
		fs.writeFileSync(output_file, `${envdata}\n`);
		console.log(`${output_file} created.`);
	}
};

export default convert;
