import {
  CognitoIdentityClient,
  GetCredentialsForIdentityCommand,
  GetCredentialsForIdentityCommandOutput,
  GetIdCommand,
  NotAuthorizedException,
  TooManyRequestsException,
} from '@aws-sdk/client-cognito-identity';
import {
  CognitoIdentityProvider,
  InitiateAuthCommandOutput,
  UnauthorizedException,
} from '@aws-sdk/client-cognito-identity-provider';
import { MissingIdError, TooManyRequestsError, UnauthorizedError, UnknownError } from './errors.js';

export interface UsernamePassword {
  username: string;
  password: string;
}

export interface RefreshToken {
  refreshToken: string;
}

export interface Tokens {
  refreshToken: string;
  accessToken: string;
  idToken: string;
}

export interface Credentials {
  AccessKeyId: string;
  SecretKey: string;
  SessionToken: string;
  Expiration: Date;
}

function isCompleteCredentials(
  cred: GetCredentialsForIdentityCommandOutput['Credentials']
): cred is Credentials {
  return !!cred?.AccessKeyId && !!cred.SecretKey && !!cred.SessionToken;
}

export class Auth {
  private client: CognitoIdentityProvider;
  private fedClient: CognitoIdentityClient;
  private clientId: string | undefined;
  private userPoolId: string | undefined;
  private identityPoolId: string | undefined;

  /**
   * Construct an authorization client.
   *
   * @param client_id - The client ID of the application provided by Scribe.
   * @deprecated Use the constructor with an object instead.
   */
  constructor(clientId: string);
  /**
   * Construct an authorization client.
   * @param params - The parameters to construct the client.
   * @param params.clientId - The client ID of the application provided by Scribe.
   * @param params.userPoolId - The user pool ID provided by Scribe.
   * @param params.identityPoolId - The identity pool ID provided by Scribe.
   */
  constructor(params: { clientId?: string; userPoolId?: string; identityPoolId?: string });
  constructor(
    params: string | { clientId?: string; userPoolId?: string; identityPoolId?: string }
  ) {
    const region = 'eu-west-2';
    this.client = new CognitoIdentityProvider({
      region,
    });
    this.fedClient = new CognitoIdentityClient({
      region,
    });
    this.clientId = params instanceof Object ? params.clientId : params;
    this.userPoolId = params instanceof Object ? params.userPoolId : undefined;
    this.identityPoolId = params instanceof Object ? params.identityPoolId : undefined;
  }

  /**
  Creates a new password for a user.
  @param username - Username (usually an email address).
  @param password - Password associated with this username.
  @param new_password - New password for this username.
  @returns A boolean indicating the success of the password update.
  */
  async changePassword(username: string, password: string, newPassword: string) {
    try {
      const responseInitiate = await this.initiateAuthFlow(username, password);
      const challengeName = responseInitiate.ChallengeName;
      if (challengeName) {
        if (!this.clientId) throw new MissingIdError('Missing client ID');
        return await this.respondToAuthChallenge(responseInitiate, username, newPassword);
      } else {
        const authResult = responseInitiate.AuthenticationResult;
        const accessToken = authResult?.AccessToken;
        await this.client.changePassword({
          AccessToken: accessToken,
          PreviousPassword: password,
          ProposedPassword: newPassword,
        });
        return true;
      }
    } catch (err) {
      if (err instanceof NotAuthorizedException) throw new UnauthorizedError(err.message, err);
      else if (err instanceof MissingIdError) throw err;
      else if (err instanceof TooManyRequestsException)
        throw new TooManyRequestsError(err.message, err);
      else throw err;
    }
  }

  private async respondToAuthChallenge(
    response: InitiateAuthCommandOutput,
    username: string,
    newPassword: string
  ) {
    const { Session, ChallengeParameters, ChallengeName } = response;
    const userIdSRP = ChallengeParameters?.['USER_ID_FOR_SRP'];
    const requiredAttributes = ChallengeParameters?.['requiredAttributes'];
    await this.client.respondToAuthChallenge({
      Session: Session!,
      ClientId: this.clientId,
      ChallengeName: ChallengeName,
      ChallengeResponses: {
        username,
        newPassword,
        userIdSRP: userIdSRP!,
        ...(requiredAttributes && {
          requiredAttributes: requiredAttributes,
        }),
      },
    });
    return true;
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
    if (!this.clientId) throw new MissingIdError('Missing client ID');
    try {
      await this.client.confirmForgotPassword({
        ClientId: this.clientId,
        Username: username,
        ConfirmationCode: confirmationCode,
        Password: password,
      });
      return true;
    } catch (err) {
      throw err instanceof NotAuthorizedException ? new UnauthorizedError(err.message, err) : err;
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
    if ('username' in param && 'password' in param) {
      const { username, password } = param;
      return await this.getTokensWithPair(username, password);
    } else {
      return await this.getTokensFromRefresh(param.refreshToken);
    }
  }

  private async getTokensWithPair(username: string, password: string): Promise<Tokens> {
    try {
      const response = await this.initiateAuthFlow(username, password);
      const result = response.AuthenticationResult;
      return {
        refreshToken: result?.RefreshToken ?? '',
        accessToken: result?.AccessToken ?? '',
        idToken: result?.IdToken ?? '',
      };
    } catch (err) {
      if (err instanceof UnauthorizedException)
        throw new UnauthorizedError(
          'Username and/or Password are incorrect. Could not get tokens',
          err
        );
      else throw err;
    }
  }

  private async getTokensFromRefresh(refreshToken: string): Promise<Tokens> {
    if (!this.clientId) throw new MissingIdError('Missing client ID');
    try {
      const response = await this.client.initiateAuth({
        ClientId: this.clientId,
        AuthFlow: 'REFRESH_TOKEN',
        AuthParameters: {
          REFRESH_TOKEN: refreshToken,
        },
      });
      const result = response.AuthenticationResult;
      return {
        refreshToken: refreshToken,
        accessToken: result?.AccessToken ?? '',
        idToken: result?.IdToken ?? '',
      };
    } catch (err) {
      throw err instanceof NotAuthorizedException ? new UnauthorizedError(err.message, err) : err;
    }
  }

  async getFederatedId(idToken: string): Promise<string> {
    if (!this.userPoolId) throw new MissingIdError('Missing user pool ID');
    if (!this.identityPoolId) throw new MissingIdError('Missing federated pool ID');
    try {
      const response = await this.fedClient.send(
        new GetIdCommand({
          IdentityPoolId: this.identityPoolId,
          Logins: {
            [`cognito-idp.eu-west-2.amazonaws.com/${this.userPoolId}`]: idToken,
          },
        })
      );
      if (!response.IdentityId) throw new UnknownError('Could not retrieve federated id');
      return response.IdentityId;
    } catch (err) {
      if (err instanceof NotAuthorizedException)
        throw new UnauthorizedError('Could not retrieve federated id', err);
      else if (err instanceof TooManyRequestsException)
        throw new TooManyRequestsError('Too many requests. Try again later');
      throw err;
    }
  }

  async getFederatedCredentials(id: string, idToken: string): Promise<Credentials> {
    if (!this.userPoolId) throw new MissingIdError('Missing user pool ID');
    try {
      const response = await this.fedClient.send(
        new GetCredentialsForIdentityCommand({
          IdentityId: id,
          Logins: {
            [`cognito-idp.eu-west-2.amazonaws.com/${this.userPoolId}`]: idToken,
          },
        })
      );
      if (!isCompleteCredentials(response.Credentials))
        throw new UnknownError('Could not retrieve federated credentials');
      return response.Credentials;
    } catch (err) {
      if (err instanceof NotAuthorizedException)
        throw new UnauthorizedError('Could not retrieve federated credentials', err);
      else if (err instanceof TooManyRequestsException)
        throw new TooManyRequestsError('Too many requests. Try again later');
      throw err;
    }
  }

  // async revokeRefreshToken(refreshToken: string): Promise<boolean> {
  //   /**
  //   Revokes all of the access tokens generated by the specified refresh token.
  //   After the token is revoked, the user cannot use the revoked token.
  //   @param refresh_token - Refresh token to be revoked.
  //   @returns A boolean indicating the success of the revocation.
  //   */
  //   const response = await this.clientUnsigned.revokeToken({
  //     Token: refreshToken,
  //     ClientId: this.clientId,
  //   });
  //   const statusCode = response.$metadata.httpStatusCode;
  //   if (statusCode === 200) {
  //     return true;
  //   }
  //   throw statusCode === 400
  //     ? new TooManyRequestsError('Too many requests. Try again later')
  //     : new Error('InternalServerError: try again later');
  // }

  // async revokeRefreshToken(refreshToken: string) {
  //   try {
  //     const command = new RevokeTokenCommand({
  //       ClientId: this.clientId,
  //       Token: refreshToken,
  //     });
  //     const client2 = new CognitoIdentityProvider({
  //       region: 'eu-west-2',
  //     });
  //     return await client2.send(command);
  //   } catch (err) {
  //     console.error('Error revoking token:', err);
  //     throw err;
  //   }
  // }

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
}
