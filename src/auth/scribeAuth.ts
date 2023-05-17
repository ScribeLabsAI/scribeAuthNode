import { CognitoIdentityProvider as CognitoIdentityServiceProvider } from '@aws-sdk/client-cognito-identity-provider';
import AWS from 'aws-sdk';

AWS.config.update({ region: 'eu-west-2' });

interface UsernamePassword {
  username: string;
  password: string;
}

interface RefreshToken {
  refreshToken: string;
}

interface Tokens {
  refreshToken: string;
  accessToken: string;
  idToken: string;
}

class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

class TooManyRequestsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TooManyRequestsError';
  }
}

class ScribeAuth {
  private client: CognitoIdentityServiceProvider;
  private clientId: string;

  constructor(clientId: string) {
    /**
     * Construct an authorization client.
     *
     * @param client_id - The client ID of the application provided by Scribe.
     */

    this.client = new CognitoIdentityServiceProvider({
      region: 'eu-west-2',
    });
    this.clientId = clientId;
  }

  async changePassword(username: string, password: string, newPassword: string) {
    /**
    Creates a new password for a user.
    @param username - Username (usually an email address).
    @param password - Password associated with this username.
    @param new_password - New password for this username.
    @returns A boolean indicating the success of the password update.
    */
    try {
      const responseInitiate = await this.initiateAuthFlow(username, password);
      const challengeName = responseInitiate.ChallengeName;
      if (challengeName) {
        const session = responseInitiate.Session!;
        const challengeParams = responseInitiate.ChallengeParameters;
        const userIdSRP = challengeParams?.['USER_ID_FOR_SRP'];
        try {
          await this.client.respondToAuthChallenge({
            Session: session,
            ClientId: this.clientId,
            ChallengeName: challengeName,
            ChallengeResponses: {
              USERNAME: username,
              NEW_PASSWORD: newPassword,
              USER_ID_FOR_SRP: userIdSRP!,
            },
            ClientMetadata: {
              newPassword,
            },
          });
          return true;
        } catch {
          throw new Error('InternalServerError: try again later');
        }
      } else {
        try {
          const authResult = responseInitiate.AuthenticationResult;
          const accessToken = authResult?.AccessToken;
          await this.client.changePassword({
            AccessToken: accessToken,
            PreviousPassword: password,
            ProposedPassword: newPassword,
          });
          return true;
        } catch {
          throw new TooManyRequestsError(
            'Password has been changed too many times. Try again later'
          );
        }
      }
    } catch {
      throw new UnauthorizedError('Username and/or Password are incorrect');
    }
  }

  async forgotPassword(username: string, password: string, confirmationCode: string) {
    /**
     * Allows a user to enter a confirmation code sent to their email to reset a forgotten password.
     *
     * @param username - Username (usually an email address).
     * @param password - Password associated with this username.
     * @param confirmation_code - Confirmation code sent to the user's email.
     * @returns A boolean indicating the success of the password reset.
     */
    try {
      await this.client.confirmForgotPassword({
        ClientId: this.clientId,
        Username: username,
        ConfirmationCode: confirmationCode,
        Password: password,
      });
      return true;
    } catch {
      throw new UnauthorizedError(
        'Username, Password and/or Confirmation_code are incorrect. Could not reset password'
      );
    }
  }

  async getTokens(param: UsernamePassword | RefreshToken): Promise<Tokens> {
    /**
     * A user gets their tokens (refresh_token, access_token, and id_token).
     *
     * @param username - Username (usually an email address).
     * @param password - Password associated with this username.
     *                   OR
     * @param refresh_token - Refresh token to use.
     * @returns Tokens - Object containing the refresh_token, access_token, and id_token.
     *                   { "refresh_token": string, "access_token": string, "id_token": string }
     */
    const authResult = 'AuthenticationResult';
    if ('username' in param && 'password' in param) {
      const { username, password } = param;
      try {
        const response = await this.initiateAuthFlow(username, password);
        const result = response[authResult];
        return {
          refreshToken: result?.RefreshToken ?? '',
          accessToken: result?.AccessToken ?? '',
          idToken: result?.IdToken ?? '',
        };
      } catch {
        throw new UnauthorizedError('Username and/or Password are incorrect. Could not get tokens');
      }
    } else {
      try {
        const response = await this.getTokensFromRefresh(param.refreshToken);
        const result = response[authResult];
        return {
          refreshToken: param.refreshToken,
          accessToken: result?.AccessToken ?? '',
          idToken: result?.IdToken ?? '',
        };
      } catch {
        throw new UnauthorizedError('RefreshToken is incorrect. Could not get tokens');
      }
    }
  }

  private async initiateAuthFlow(username: string, password: string) {
    return await this.client.initiateAuth({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
    });
  }

  private async getTokensFromRefresh(refreshToken: string) {
    return await this.client.initiateAuth({
      ClientId: this.clientId,
      AuthFlow: 'REFRESH_TOKEN',
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    });
  }
}

export { ScribeAuth, Tokens, UnauthorizedError, TooManyRequestsError };
