const commonjs = require("@rollup/plugin-commonjs");
const resolve = require("@rollup/plugin-node-resolve");
const replace = require("@rollup/plugin-replace");
const json = require("@rollup/plugin-json");

module.exports = {
	input: "src/index.js",
	output: {
		file: "dist/index.js",
		format: "cjs",
	},
	external: ["crypto", "fs", "path", "os", "commander", "ms", "isbinaryfile"],
	plugins: [
		replace({
			preventAssignment: true,
			"process.env.API_BASE_URL": JSON.stringify(process.env.API_BASE_URL),
			delimiters: ["", ""],
		}),
		json(),
		resolve({ preferBuiltins: true }),
		commonjs(),
	],
};
