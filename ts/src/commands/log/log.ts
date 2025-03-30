import program from "../program";

program
	.command("log")
	.argument("<env-name>", "A unique identifier for the env")
	.argument("<input-file>", "A unique identifier for the file")
	.description("Generate keys to receive secrets only readable on this machine")
	.action(async (env: string, input_file: string) => {
		try {
			if (!input_file) {
				console.log("no input file");
				process.exit(1);
			}

			if (!env) {
				console.log("invalid usage, Try `clienv log --help` for help.");
				return;
			}

			const input_file_ext = input_file.split(".").slice(-1)[0];

			if (input_file_ext === "json") {
				const rawdata = fs.readFileSync(input_file);
				const data = JSON.parse(rawdata);
				const key = Object.keys(data).find((key) => key === env);
				if (key) {
					console.log(`{
        ${key}: ${data[key]}
}`);
				} else {
					console.log("env not found");
				}
			} else {
				console.log(`logging for *.${input_file_ext} not yet implemented`);
				return;
			}
		} catch (error) {
			console.error(`Failed to initialize ${input_file}:`, error);
			process.exit(1);
		}
	});
