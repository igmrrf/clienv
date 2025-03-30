import { execSync } from "node:child_process";
import fs from "node:fs";

// Mock fs functions
jest.mock("node:fs", () => ({
	...jest.requireActual("fs"),
	writeFileSync: jest.fn(),
	readFileSync: jest.fn(),
}));

describe("Convert Command Tests", () => {
	beforeEach(() => {
		jest.clearAllMocks();
		// Mock readFileSync to return a sample JSON
		fs.readFileSync.mockReturnValue(
			JSON.stringify({
				TEST_KEY: "test_value",
				ANOTHER_KEY: "another_value",
			}),
		);
	});

	test("should convert JSON to env file with default settings", () => {
		// Execute the command
		try {
			execSync("node main.js convert --file=test.json", { stdio: "pipe" });
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if writeFileSync was called with correct parameters
		expect(fs.writeFileSync).toHaveBeenCalledWith(
			"test.env",
			"TEST_KEY='test_value'\nANOTHER_KEY='another_value'\n",
		);
	});

	test("should convert JSON to env file with prefix", () => {
		// Execute the command
		try {
			execSync("node main.js convert --file=test.json --prefix=NEXT_PUBLIC_", {
				stdio: "pipe",
			});
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if writeFileSync was called with correct parameters
		expect(fs.writeFileSync).toHaveBeenCalledWith(
			"test.env",
			"NEXT_PUBLIC_TEST_KEY='test_value'\nNEXT_PUBLIC_ANOTHER_KEY='another_value'\n",
		);
	});

	test("should convert JSON to env file with custom output file", () => {
		// Execute the command
		try {
			execSync("node main.js convert --file=test.json --out=custom.env", {
				stdio: "pipe",
			});
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if writeFileSync was called with correct parameters
		expect(fs.writeFileSync).toHaveBeenCalledWith(
			"custom.env",
			"TEST_KEY='test_value'\nANOTHER_KEY='another_value'\n",
		);
	});

	test("should handle embed option correctly", () => {
		// Create a spy on console.log
		const consoleSpy = jest.spyOn(console, "log");

		// Execute the command
		try {
			execSync("node main.js convert --file=test.json --embed=true", {
				stdio: "pipe",
			});
		} catch (error) {
			console.error(error.stdout.toString());
			console.error(error.stderr.toString());
			throw error;
		}

		// Check if console.log was called with the embedded format
		expect(consoleSpy).toHaveBeenCalledWith(
			expect.stringContaining("TEST_KEY: TEST_KEY"),
		);
		expect(consoleSpy).toHaveBeenCalledWith(
			expect.stringContaining("ANOTHER_KEY: ANOTHER_KEY"),
		);

		consoleSpy.mockRestore();
	});
});

