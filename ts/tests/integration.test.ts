import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

describe("CLIENV Integration Tests", () => {
	const testJsonPath = path.join(__dirname, "test-config.json");
	const testEnvPath = path.join(__dirname, "test-config.env");

	beforeEach(() => {
		// Create a test JSON file
		const testData = {
			TEST_KEY: "test_value",
			ANOTHER_KEY: "another_value",
		};

		fs.writeFileSync(testJsonPath, JSON.stringify(testData, null, 2));

		// Remove test env file if it exists
		if (fs.existsSync(testEnvPath)) {
			fs.unlinkSync(testEnvPath);
		}
	});

	afterEach(() => {
		// Clean up test files
		if (fs.existsSync(testJsonPath)) {
			fs.unlinkSync(testJsonPath);
		}

		if (fs.existsSync(testEnvPath)) {
			fs.unlinkSync(testEnvPath);
		}
	});

	test("should convert JSON to env file and verify content", () => {
		// Execute the convert command
		execSync(
			`node ${path.join(__dirname, "../main.js")} convert --file=${testJsonPath} --out=${testEnvPath}`,
			{ stdio: "pipe" },
		);

		// Verify the env file was created
		expect(fs.existsSync(testEnvPath)).toBe(true);

		// Read the content of the env file
		const envContent = fs.readFileSync(testEnvPath, "utf8");

		// Verify the content
		expect(envContent).toContain("TEST_KEY='test_value'");
		expect(envContent).toContain("ANOTHER_KEY='another_value'");
	});
});

