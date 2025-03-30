import fs from "node:fs";
import inquirer from "inquirer";
import dotenv from "dotenv";

// Mock dependencies
jest.mock("fs", () => ({
	...jest.requireActual("fs"),
	readdirSync: jest.fn(),
	createWriteStream: jest.fn(() => ({
		write: jest.fn(),
		end: jest.fn(),
	})),
}));

jest.mock("inquirer", () => ({
	createPromptModule: jest.fn(() => jest.fn()),
}));

jest.mock("dotenv", () => ({
	config: jest.fn(),
}));

describe("Sample Command Tests", () => {
	beforeEach(() => {
		jest.clearAllMocks();

		// Mock readdirSync to return sample files
		fs.readdirSync.mockReturnValue([
			{ isFile: () => true, name: ".env.example" },
			{ isFile: () => true, name: ".env.dev" },
			{ isFile: () => false, name: "not-a-file" },
		]);

		// Mock inquirer prompt to return sample answers
		const mockPrompt = jest.fn();
		mockPrompt
			.mockResolvedValueOnce({
				env_file: ".env.example",
				env_name: ".env.local",
			})
			.mockResolvedValueOnce({
				DB_HOST: "localhost",
				DB_PORT: "5432",
			});

		inquirer.createPromptModule.mockReturnValue(mockPrompt);

		// Mock dotenv.config to return parsed env variables
		dotenv.config.mockReturnValue({
			parsed: {
				DB_HOST: "localhost",
				DB_PORT: "5432",
			},
		});
	});

	test("should create a new env file based on template", async () => {
		// Import the sample function
		const sample = require("../lib/sample").default;

		// Execute the sample function
		await sample();

		// Check if createWriteStream was called with the correct file name
		expect(fs.createWriteStream).toHaveBeenCalledWith(
			".env.local",
			expect.any(Object),
		);

		// Check if the write method was called for each env variable
		const writeStream = fs.createWriteStream();
		expect(writeStream.write).toHaveBeenCalledWith("DB_HOST='localhost'\n");
		expect(writeStream.write).toHaveBeenCalledWith("DB_PORT='5432'\n");
		expect(writeStream.end).toHaveBeenCalled();
	});
});

