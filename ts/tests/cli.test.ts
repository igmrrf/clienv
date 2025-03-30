const { execSync } = require('child_process');

describe('CLI Command Tests', () => {
  test('should display help message', () => {
    const output = execSync('node main.js --help', { encoding: 'utf8' });
    expect(output).toContain('usage:');
    expect(output).toContain('clienv convert');
    expect(output).toContain('clienv log');
  });
  
  test('should display error for invalid action', () => {
    const output = execSync('node main.js invalid-action', { encoding: 'utf8' });
    expect(output).toContain('invalid usage');
  });
  
  test('should display error for convert without file', () => {
    const output = execSync('node main.js convert', { encoding: 'utf8' });
    expect(output).toContain('invalid usage');
  });
  
  test('should display error for log without env variable', () => {
    const output = execSync('node main.js log', { encoding: 'utf8' });
    expect(output).toContain('invalid usage');
  });
});