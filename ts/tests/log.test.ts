import fs from "node:fs";
import { execSync } from "node:child_process";

// Mock fs functions
jest.mock("fs", () => ({
	...jest.requireActual("fs"),
	readFileSync: jest.fn(),
}));

describe("Log Command Tests", () => {
	beforeEach(() => {
		jest.clearAllMocks();
		// Mock readFileSync to return a sample JSON
		fs.readFileSync.mockReturnValue(
			JSON.stringify({
				MONGO_URL: "mongodb://localhost:27017",
				API_KEY: "test_api_key",
			}),
		);
	});

	test("should log environment variable from JSON file", () => {
		// Create a spy on console.log
		const consoleSpy = jest.spyOn(console, "log");

		// Execute the command
		try {
			execSync("node main.js log MONGO_URL --file=config.json", {
				stdio: "pipe",
			});
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if console.log was called with the correct output
		expect(consoleSpy).toHaveBeenCalledWith(
			expect.stringContaining("MONGO_URL: mongodb://localhost:27017"),
		);

		consoleSpy.mockRestore();
	});

	test("should handle non-existent environment variable", () => {
		// Create a spy on console.log
		const consoleSpy = jest.spyOn(console, "log");

		// Execute the command
		try {
			execSync("node main.js log NON_EXISTENT_KEY --file=config.json", {
				stdio: "pipe",
			});
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if console.log was called with the correct output
		expect(consoleSpy).toHaveBeenCalledWith("env not found");

		consoleSpy.mockRestore();
	});
});

