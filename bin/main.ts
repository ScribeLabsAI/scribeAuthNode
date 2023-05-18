import { createCommand } from 'commander';
import { ScribeAuth } from '../dist/auth/scribeAuth.js';

const program = createCommand('get_tokens').arguments('<clientid> <username> <password>');
program.parse(process.argv);

const [clientid, username, password] = program.args;

if (clientid === undefined || username === undefined || password === undefined) {
  throw new Error('Missing arguments');
}

const access = new ScribeAuth(clientid);
const tokens = await access.getTokens({ username, password });
console.log(tokens);
