const log = () => {
	const env = args.log || args._[1];
	let input_file = args.file;

	if (!input_file) {
		console.log("no input file");
		input_file = "./config/development.json";
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
};

export default log;
