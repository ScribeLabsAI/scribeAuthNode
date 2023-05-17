import { describe, expect, test } from '@jest/globals';
import * as dotenv from 'dotenv';
import { readFile } from 'node:fs/promises';
import { ScribeAuth, Tokens } from '../dist/auth/scribeAuth.js';

dotenv.config();

const content = await readFile('./tests/.env', 'utf8');
const buffer = Buffer.from(content);
const data = dotenv.parse(buffer);
const clientId = data['CLIENT_ID']!;
const username = data['USER']!;
const password = data['PASSWORD']!;
const access = new ScribeAuth(clientId);

describe('Get tokens', () => {
  test('Username and password successfully', async () => {
    const tokens = await access.getTokens({ username, password });
    expect(assertTokens(tokens)).toBeTruthy();
  });
  // TODO: add more tests (wrong username, wrong password, empty username, empty password, empty username and password, right refresh token, wrong refresh token)
});

function assertTokens(tokens: Tokens): boolean {
  return (
    !!tokens.accessToken &&
    !!tokens.idToken &&
    !!tokens.refreshToken &&
    tokens.accessToken !== tokens.idToken &&
    tokens.accessToken !== tokens.refreshToken &&
    tokens.idToken !== tokens.refreshToken
  );
}
