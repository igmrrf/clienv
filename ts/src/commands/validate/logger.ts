/* eslint-disable no-console */
import chalk from "chalk";
import { summer } from "gradient-string";

/**
 * Short month names
 */
export const monthNames = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"June",
	"July",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
];

type ILog = string | number | object;

export const padStringTwoNumbers = (value: number) =>
	`${value}`.padStart(2, "0");

export const formatDate = (): string => {
	const date = new Date();
	const day = padStringTwoNumbers(date.getDate());
	const month = monthNames[date.getMonth()];
	const year = padStringTwoNumbers(date.getFullYear());
	const hour = padStringTwoNumbers(date.getHours());
	const minutes = padStringTwoNumbers(date.getMinutes());
	const seconds = padStringTwoNumbers(date.getSeconds());
	const milliseconds = `${date.getMilliseconds()}`.padStart(3, "0");
	return `📅 ${day}/${month}/${year} 🕐 ${hour}:${minutes}:${seconds}:${milliseconds} `;
};

export const withDate = (str: string, displayDate = false) =>
	`${displayDate ? formatDate() : ""}${str}`;

export const logError = (error: ILog) => {
	console.info(
		withDate(`${chalk.bold.red("[❌ ERROR]")}  ${chalk.red(error)}`),
	);
};

export const logInfo = (info: ILog) => {
	console.info(withDate(`${chalk.bold.green("📗 [ INFO ]")}  ${info}`));
};

export const logWarn = (info: ILog) => {
	console.warn(withDate(`${chalk.bold.yellow("🚧 [ WARN ]")} ${info}`));
};

export const logAlert = (info: ILog) => {
	console.warn(
		withDate(`${chalk.bold.red("❗ [ ALERT ] 💢")} ${chalk.underline(info)}`),
	);
};

export const log = (value: ILog) => {
	console.warn(withDate(`${chalk.bold.whiteBright("[📋 LOG]")} ${value}`));
};

export const logStartupBanner = () =>
	console.log(`
${chalk.bold(summer("[ DOTENV-CHECKER ]"))} ${chalk.cyanBright("- Initializing checks for .env files consistency & sync...")}
`);

export const logEnvFileCreated = (envFile: string) => () => {
	const envFileName = envFile.split("/").slice(-1);
	logInfo(
		chalk.green(
			`✅ ${chalk.underline(envFileName)} file created successfully!`,
		),
	);
};
