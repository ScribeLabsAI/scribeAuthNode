#! /usr/bin/env node

import { Auth } from '@scribelabsai/auth';
import { program } from 'commander';

program
  .command('token')
  .description('Get all the JWTs (id, access and refresh) given a user/password pair')
  .arguments('<clientid> <username> <password>')
  .action(async (clientid: string, username: string, password: string) => {
    const auth = new Auth({ clientId: clientid });
    const tokens = await auth.getTokens({ username, password });
    console.info(tokens);
  });

program
  .command('credentials')
  .description('Get the credentials using an id token')
  .arguments('<userpoolid> <fedid> <token>')
  .action(async (userpoolid: string, fedid: string, token: string) => {
    const auth = new Auth({ userPoolId: userpoolid, identityPoolId: fedid });
    const fedUserId = await auth.getFederatedId(token);
    const credentials = await auth.getFederatedCredentials(fedUserId, token);
    console.info(credentials);
  });

program.parse(process.argv);
