import { Auth } from '@scribelabsai/auth';
import { createCommand } from 'commander';

const program = createCommand('Auth').arguments('<clientid> <username> <password>');
program.parse(process.argv);

const [clientid, username, password] = program.args;

if (clientid === undefined || username === undefined || password === undefined) {
  throw new Error('Missing arguments');
}

const access = new Auth(clientid);
const tokens = await access.getTokens({ username, password });
console.log(tokens);
