import { HttpRequest } from '@aws-sdk/protocol-http';
import { describe, expect, test } from '@jest/globals';
import { Auth, Tokens } from '@scribelabsai/auth';
import * as dotenv from 'dotenv';

dotenv.config();

const clientId = process.env['CLIENT_ID']!;
const clientId2 = process.env['CLIENT_ID2']!;
const username = process.env['USER']!;
const password = process.env['PASSWORD']!;
const password2 = process.env['PASSWORD2']!;
const userPoolId = process.env['USER_POOL_ID']!;
const userPoolId2 = process.env['USER_POOL_ID2']!;
const federatedPoolId = process.env['FEDERATED_POOL_ID']!;
const access = new Auth({ clientId, userPoolId });
const poolAccess = new Auth({
  clientId: clientId2,
  userPoolId: userPoolId2,
  identityPoolId: federatedPoolId,
});

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

describe('Federated Credentials', () => {
  test('Get federated id passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password: password2 });
    const idToken = tokens.idToken;
    const federatedId = await poolAccess.getFederatedId(idToken);
    expect(federatedId).toBeDefined();
  });
  test('Get federated id fails', async () => {
    await expect(poolAccess.getFederatedId('idToken')).rejects.toThrow();
  });
  test('Get federated id with NO identityPoolId fails', async () => {
    const tokens = await access.getTokens({ username, password });
    const idToken = tokens.idToken;
    await expect(access.getFederatedId(idToken)).rejects.toThrow();
  });

  test('Get credentials passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password: password2 });
    const idToken = tokens.idToken;
    const federatedId = await poolAccess.getFederatedId(idToken);
    const credentials = await poolAccess.getFederatedCredentials(federatedId, idToken);
    expect(credentials).toBeDefined();
    expect(credentials.AccessKeyId).toBeDefined();
    expect(credentials.SecretKey).toBeDefined();
    expect(credentials.SessionToken).toBeDefined();
    expect(credentials.Expiration).toBeDefined();
  });
  test('Get credentials fails', async () => {
    const tokens = await poolAccess.getTokens({ username, password: password2 });
    const idToken = tokens.idToken;
    await expect(poolAccess.getFederatedCredentials('id', idToken)).rejects.toThrow();
  });
});

describe('Get Signature for requests', () => {
  test('Passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password: password2 });
    const idToken = tokens.idToken;
    const federatedId = await poolAccess.getFederatedId(idToken);
    const credentials = await poolAccess.getFederatedCredentials(federatedId, idToken);
    const url: URL = new URL('https://google.com');
    const request = new HttpRequest({
      hostname: url.hostname,
      path: url.pathname,
      method: 'GET',
    });
    const signature = await poolAccess.getSignatureForRequest(request, credentials);
    expect(signature).toBeDefined();
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
