import program from "../program";

const fs = require("node:fs");

program
	.command("convert")
	.argument("<input-file>", "An input file identifier for this machine")
	.argument("<output-file>", "An output file identifier for this machine")
	.argument("<prefix>", "An output file identifier for this machine")
	.argument("<suffix>", "An output file identifier for this machine")
	.description("Generate keys to receive secrets only readable on this machine")
	.action(async (input_file, out, embed, suffix = "", prefix = "") => {
		try {
			const input_file_ext = input_file.split(".").slice(-1)[0];
			const input_file_stem = input_file.split(".").slice(0, -1).join();
			const output_file = out ? out : `${input_file_stem}.env`;

			if (input_file_ext !== "json") {
				console.log(
					"the file is not *.json. try `clienv convert --help` for help",
				);
			}

			const rawdata = fs.readFileSync(input_file);
			const data = JSON.parse(rawdata);

			if (embed) {
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
		} catch (error) {
			console.error(`Failed to initialize ${out}:`, error);
			process.exit(1);
		}
	});
