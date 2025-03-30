import fs from "node:fs";
import inquirer from "inquirer";
import dotenv from "dotenv";
const prompt = inquirer.createPromptModule();

const sample = () => {
	const query = fs.readdirSync(process.cwd(), { withFileTypes: true });
	const files = query
		.filter((file) => file.isFile() && file.name.startsWith("."))
		.map((file) => file.name);
	const questions = [
		{
			type: "rawlist",
			name: "env_file",
			message: "Which .env template would you use?",
			choices: files,
		},
		{
			type: "input",
			name: "env_name",
			message: "name of your environment file",
			default: ".env",
		},
	];

	prompt(questions).then((answers) => {
		const result = dotenv.config({ path: answers.env_file });
		if (result.error) {
			throw result.error;
		}

		const sample_variables = [];
		if (result.parsed) {
			for (const [key, value] of Object.entries(result.parsed)) {
				sample_variables.push({
					type: "input",
					name: key,
					message: key,
					default: value,
				});
			}
			const env_name = answers.env_name;
			console.log(answers);

			prompt(sample_variables).then((answers) => {
				console.log({ answers });
				const wstream = fs.createWriteStream(env_name, {
					flags: "a+",
				});
				for (const [key, value] of Object.entries(answers)) {
					const line = `${key}='${value}'\n`;
					wstream.write(line);
				}
				wstream.end();
			});
		}
	});
};
export default sample;
