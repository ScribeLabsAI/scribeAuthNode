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
  test('Username and password passes', async () => {
    const tokens = await access.getTokens({ username, password });
    expect(assertTokens(tokens)).toBeTruthy();
  });
  test('Wrong username fails', async () => {
    await expect(access.getTokens({ username: 'username', password })).rejects.toThrow();
  });
  test('Wrong password fails', async () => {
    await expect(access.getTokens({ username, password: 'password' })).rejects.toThrow();
  });

  test('Empty username fails', async () => {
    await expect(access.getTokens({ username: '', password })).rejects.toThrow();
  });
  test('Empty password fails', async () => {
    await expect(access.getTokens({ username, password: '' })).rejects.toThrow();
  });
  test('Empty username and password fails', async () => {
    await expect(access.getTokens({ username: '', password: '' })).rejects.toThrow();
  });
  test('RefreshToken passes', async () => {
    const refreshToken = await getRefreshToken();
    const tokens = await access.getTokens({ refreshToken });
    expect(assertTokens(tokens)).toBeTruthy();
  });
  test('Wrong refreshToken fails', async () => {
    await expect(access.getTokens({ refreshToken: 'refresh_token' })).rejects.toThrow();
  });
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

async function getRefreshToken() {
  const tokens = await access.getTokens({ username, password });
  return tokens.refreshToken;
}
