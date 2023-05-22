import { describe, expect, test } from '@jest/globals';
import { Auth, Tokens } from '@scribelabsai/auth';
import * as dotenv from 'dotenv';

dotenv.config();

const clientId = process.env['CLIENT_ID']!;
const username = process.env['USER']!;
const password = process.env['PASSWORD']!;
const access = new Auth(clientId);

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

// RevokeToken is not working yet and we're working on it.
// describe('Revoke', () => {
//   test('Real RefreshToken and passes', async () => {
//     const refreshToken = await getRefreshToken();
//     expect(await access.revokeRefreshToken(refreshToken)).toBeTruthy();
//   });
// });

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
