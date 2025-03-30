#!/usr/bin/env node

const args = require("minimist")(process.argv.slice(2));
const convert = require("./convert").default;
const log = require("./log").default;
const sample = require("./sample").default;
const validate = require("./validate");
const chain = require("./chain");

const help = `
usage:
	clienv convert <input.file> <out.file> [options]
	clienv convert --file=config.json --prefix="export "
	clienv convert --file=config.json --prefix="NEXT_PUBLIC_"
	clienv convert --file=.env.local --out=config.json 
	clienv convert --file=.env.local --out=config.json --embed=VUE_APP_

	clienv log <env.variable> [options]
	clienv log MONGO_URL --file=".env.local"
	clienv log --log=MONGO_URL" --file=".env.local"
	clienv log --log=MONGO_URL --file=".env.local" --out=echo

	clienv generate
	clienv generate --sample-file=sample 
  clienv validate -s .env.schema -e .env.local

  clienv validate --env .env.local               Run the command with a custom env file'
  clienv validate --schema .env.schema           Run the command with a custom schema file
  clienv validate -s .env.example -e .env.dev    Run the command with a custom env and schema file

  clienv template --env .env                    Run the command to create a template for your .env
  clienv validate .env.local
  clienv validate .env.production

  #### Setup your encryption key
  echo "your_password_here" >> .env.pass

  clienv encrypt .env -o .env.enc

  clienv decrypt .env.enc -o .env

  clienv encrypt .env                 # Looks for $DOTENV_PASS or .env.pass
  clienv encrypt .env.prod            # Looks for $DOTENV_PROD_PASS or .env.prod.pass

  clienv decrypt .env.prod.enc        # Looks for $DOTENV_PROD_PASS or .env.prod.pass
  clienv decrypt .env.prod.encrypted  # Looks for $DOTENV_PROD_PASS or .env.prod.pass
  clienv decrypt .env.prod.suffix     # Looks for $DOTENV_PROD_SUFFIX_PASS or .env.prod.suffix.pass

  ### For ensuring encrypting during commit
  echo "#!/bin/sh" >> .git/hooks/pre-commit
  echo "clienv encrypt .env -o .env.enc" >> .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit

  ### You can also add DOTENV_PASS on github for CI/CD decrypting and use

Options:
	--out\t\tthe output file path.
	--prefix\t\tthe prefix of environment variables in env file
	--suffix\t\tthe suffix of environment variables in env file
	--embed\t\tthe suffix of environment variables in env file
`;

if (args.help || args.h) {
	console.log(help);
	process.exit(0);
}

const actions = {
	convert: "convert",
	log: "log",
	sample: "sample",
	validate: "validate",
};

const action = args._[0];

if (action === actions.convert) {
	// convert json to .env
	convert(args);
} else if (action === actions.log) {
	// log env value
	log(args);
} else if (action === actions.validate) {
	// validate .env.* values against a schema
	validate();
} else if (action === actions.sample) {
	// create .env from sample
	sample();
} else {
	console.log("invalid usage, Try `clienv convert --help` for help.");
	process.exit(1);
}
