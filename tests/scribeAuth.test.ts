import { Auth, Tokens } from '@scribelabsai/auth';
import { HttpRequest } from '@smithy/protocol-http';
import * as dotenv from 'dotenv';
import { describe, expect, it } from 'vitest';
import { authenticator } from 'otplib';

dotenv.config();

const clientId = process.env['CLIENT_ID']!;
const username = process.env['USER']!;
const username2 = process.env['USER2']!;
const password = process.env['PASSWORD']!;
const userPoolId = process.env['USER_POOL_ID']!;
const federatedPoolId = process.env['FEDERATED_POOL_ID']!;
const otp = process.env['OTPCODE']!;
const access = new Auth({ clientId, userPoolId });
const poolAccess = new Auth({
  clientId: clientId,
  userPoolId: userPoolId,
  identityPoolId: federatedPoolId,
});

const mfaActivatedError = 'challenge instead of tokens';

describe('Get tokens', () => {
  it('Username and password passes', async () => {
    const tokens = await access.getTokens({ username, password });
    if ('refreshToken' in tokens && 'idToken' in tokens && 'accessToken' in tokens) {
      expect(assertTokens(tokens)).toBeTruthy();
    } else {
      throw new Error(mfaActivatedError);
    }
  });
  it('Wrong username fails', async () => {
    await expect(() => access.getTokens({ username: 'username', password })).rejects.toThrow();
  });
  it('Wrong password fails', async () => {
    await expect(() => access.getTokens({ username, password: 'password' })).rejects.toThrow();
  });

  it('Empty username fails', async () => {
    await expect(() => access.getTokens({ username: '', password })).rejects.toThrow();
  });
  it('Empty password fails', async () => {
    await expect(() => access.getTokens({ username, password: '' })).rejects.toThrow();
  });
  it('Empty username and password fails', async () => {
    await expect(() => access.getTokens({ username: '', password: '' })).rejects.toThrow();
  });
  it('RefreshToken passes', async () => {
    const refreshToken = await getRefreshToken();
    const tokens = await access.getTokens({ refreshToken });
    if ('refreshToken' in tokens && 'idToken' in tokens && 'accessToken' in tokens) {
      expect(assertTokens(tokens)).toBeTruthy();
    } else {
      throw new Error(mfaActivatedError);
    }
  });
  it('Wrong refreshToken fails', async () => {
    await expect(() => access.getTokens({ refreshToken: 'refresh_token' })).rejects.toThrow();
  });
});

describe('Federated Credentials', () => {
  it('Get federated id passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password });
    if ('idToken' in tokens) {
      const idToken = tokens.idToken;
      const federatedId = await poolAccess.getFederatedId(idToken);
      expect(federatedId).toBeDefined();
    } else {
      throw new Error(mfaActivatedError);
    }
  });
  it('Get federated id fails', async () => {
    await expect(() => poolAccess.getFederatedId('idToken')).rejects.toThrow();
  });
  it('Get federated id with NO identityPoolId fails', async () => {
    const tokens = await access.getTokens({ username, password });
    if ('idToken' in tokens) {
      const idToken = tokens.idToken;
      await expect(() => access.getFederatedId(idToken)).rejects.toThrow();
    } else {
      throw new Error(mfaActivatedError);
    }
  });

  it('Get credentials passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password });
    if ('idToken' in tokens) {
      const idToken = tokens.idToken;
      const federatedId = await poolAccess.getFederatedId(idToken);
      const credentials = await poolAccess.getFederatedCredentials(federatedId, idToken);
      expect(credentials).toBeDefined();
      expect(credentials.AccessKeyId).toBeDefined();
      expect(credentials.SecretKey).toBeDefined();
      expect(credentials.SessionToken).toBeDefined();
      expect(credentials.Expiration).toBeDefined();
    } else {
      throw new Error(mfaActivatedError);
    }
  });
  it('Get credentials fails', async () => {
    const tokens = await poolAccess.getTokens({ username, password });
    if ('idToken' in tokens) {
      const idToken = tokens.idToken;
      await expect(() => poolAccess.getFederatedCredentials('id', idToken)).rejects.toThrow();
    } else {
      throw new Error(mfaActivatedError);
    }
  });
});

describe('Get Signature for requests', () => {
  it('Passes', async () => {
    const tokens = await poolAccess.getTokens({ username, password });
    if ('idToken' in tokens) {
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
    } else {
      throw new Error(mfaActivatedError);
    }
  });
});

describe('Get tokens MFA', () => {
  it('asks for MFA', async () => {
    const challenge = await access.getTokens({ username: username2, password });
    if ('challengeName' in challenge && 'challengeParameters' in challenge && 'user' in challenge) {
      expect(challenge.user).toBeDefined();
      expect(challenge.challengeName).toBeDefined();
      expect(challenge.challengeParameters).toBeDefined();
    } else {
      throw new Error('no MFA challenge found');
    }
  });

  it(
    'get tokens with username and password successfully',
    async () => {
      const challenge = await access.getTokens({ username: username2, password });
      await sleep(61_000);
      const code = authenticator.generate(otp);
      if ('user' in challenge && 'challengeParameters' in challenge) {
        const tokens = await access.respondToAuthChallengeMfa(
          challenge.user,
          code,
          challenge.challengeParameters
        );
        expect(assertTokens(tokens)).toBeTruthy();
      } else {
        throw new Error('no MFA challenge found');
      }
    },
    { timeout: 70_000 }
  );

  it(
    'get tokens with refresh token successfully',
    async () => {
      await sleep(61_000);
      const refreshToken = await getRefreshTokenWithMFA();
      const tokens = await access.getTokens({ refreshToken });
      if ('refreshToken' in tokens && 'idToken' in tokens && 'accessToken' in tokens) {
        expect(assertTokens(tokens)).toBeTruthy();
      } else {
        throw new Error(mfaActivatedError);
      }
    },
    { timeout: 70_000 }
  );

  it('get tokens fails with wrong mfa code', async () => {
    const challenge = await access.getTokens({ username: username2, password });
    const code = '000000';
    if ('user' in challenge && 'challengeParameters' in challenge) {
      await expect(() =>
        access.respondToAuthChallengeMfa(challenge.user, code, challenge.challengeParameters)
      ).rejects.toThrow();
    } else {
      throw new Error('no MFA challenge found');
    }
  });

  it(
    'get tokens fails with expired mfa code',
    async () => {
      const challenge = await access.getTokens({ username: username2, password });
      const code = authenticator.generate(otp);
      await sleep(61_000);
      if ('user' in challenge && 'challengeParameters' in challenge) {
        await expect(() =>
          access.respondToAuthChallengeMfa(challenge.user, code, challenge.challengeParameters)
        ).rejects.toThrow();
      } else {
        throw new Error('no MFA challenge found');
      }
    },
    { timeout: 70_000 }
  );
});

// RevokeToken is not working yet and we're working on it.
// describe('Revoke', () => {
//   it('Real RefreshToken and passes', async () => {
//     const refreshToken = await getRefreshToken();
//     await expect(() => access.revokeRefreshToken(refreshToken)).toBeTruthy();
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
  if ('refreshToken' in tokens) {
    return tokens.refreshToken;
  }
  throw new Error('use getRefreshTokenWithMFA() instead');
}

async function getRefreshTokenWithMFA() {
  const challenge = await access.getTokens({ username: username2, password });
  const code = authenticator.generate(otp);
  if ('user' in challenge && 'challengeParameters' in challenge) {
    const response = await access.respondToAuthChallengeMfa(
      challenge.user,
      code,
      challenge.challengeParameters
    );
    return response.refreshToken;
  }
  throw new Error('use getRefreshToken() instead');
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
