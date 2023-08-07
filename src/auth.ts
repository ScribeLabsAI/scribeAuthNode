import { Sha256 } from '@aws-crypto/sha256-js';
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
} from '@aws-sdk/client-cognito-identity-provider';
import { HttpRequest } from '@smithy/protocol-http';
import { SignatureV4 } from '@smithy/signature-v4';
import { AuthenticationDetails, CognitoUser, CognitoUserPool } from 'amazon-cognito-identity-js';
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
  return !!cred?.AccessKeyId && !!cred.SecretKey && !!cred.SessionToken && !!cred.Expiration;
}

export class Auth {
  private client: CognitoIdentityProvider;
  private fedClient: CognitoIdentityClient | undefined;
  private clientId: string;
  private userPoolId: string;
  private identityPoolId: string | undefined;

  /**
   * Construct an authorization client.
   * @param params - The parameters to construct the client.
   * @param params.clientId - The client ID of the application provided by Scribe.
   * @param params.userPoolId - The user pool ID provided by Scribe.
   * @param params.identityPoolId - The identity pool ID provided by Scribe.
   */
  constructor(params: { clientId: string; userPoolId: string; identityPoolId?: string }) {
    const region = 'eu-west-2';
    this.client = new CognitoIdentityProvider({
      region,
    });
    this.clientId = params.clientId;
    this.userPoolId = params.userPoolId;
    this.identityPoolId = params.identityPoolId;
    if (params.identityPoolId) {
      this.fedClient = new CognitoIdentityClient({
        region,
      });
    }
  }

  /**
  Creates a new password for a user.
  @param username - Username (usually an email address).
  @param password - Password associated with this username.
  @param newPassword - New password for this username.
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
     * @param confirmationCode - Confirmation code sent to the user's email.
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
     * A user gets their tokens (refreshToken, accessToken, and idToken).
     * The password from params never abandons the user's machine.
     *
     * @param username - Username (usually an email address).
     * @param password - Password associated with this username.
     *                   OR
     * @param refreshToken - Refresh token to use.
     * @returns Tokens - Object containing the refreshToken, accessToken, and idToken.
     *                   { "refreshToken": string, "accessToken": string, "idToken": string }
     */
    if ('username' in param && 'password' in param) {
      const { username, password } = param;
      return await this.getTokensWithPair(username, password);
    } else {
      return await this.getTokensFromRefresh(param.refreshToken);
    }
  }

  private async getTokensWithPair(username: string, password: string): Promise<Tokens> {
    const authenticationDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    });
    const pool = new CognitoUserPool({ UserPoolId: this.userPoolId, ClientId: this.clientId! });
    const cognitoUser = new CognitoUser({ Username: username, Pool: pool });
    cognitoUser.setAuthenticationFlowType('USER_SRP_AUTH');
    return new Promise<Tokens>((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
          resolve({
            accessToken: result.getAccessToken().getJwtToken(),
            idToken: result.getIdToken().getJwtToken(),
            refreshToken: result.getRefreshToken().getToken(),
          });
        },
        onFailure: function (err) {
          if (err.name === 'NotAuthorizedException') {
            reject(new UnauthorizedError(err.message, err));
          } else {
            reject(err);
          }
        },
      });
    });
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
      if (err instanceof Error) {
        throw err.name === 'NotAuthorizedException' ? new UnauthorizedError(err.message, err) : err;
      }
      throw err;
    }
  }

  async getFederatedId(idToken: string): Promise<string> {
    /**
     * A user gets their federated id.
     *
     * @param idToken - Id token to use.
     * @returns A string containing the federatedId.
     */
    if (!this.userPoolId) throw new MissingIdError('Missing user pool ID');
    if (!this.fedClient)
      throw new MissingIdError(
        'Identity Pool ID is not provided. Create a new Auth object using identityPoolId'
      );
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
    /**
     * A user gets their federated credentials (AccessKeyId, SecretKey and SessionToken).
     *
     * @param id - Federated id.
     * @param idToken - Id token to use.
     * @returns Credentials - Object containing the AccessKeyId, SecretKey, SessionToken and Expiration.
     *                   { "AccessKeyId": string, "SecretKey": string, "SessionToken": string, "Expiration": string }
     */
    if (!this.userPoolId) throw new MissingIdError('Missing user pool ID');
    if (!this.fedClient)
      throw new MissingIdError(
        'Identity Pool ID is not provided. Create a new Auth object using identityPoolId'
      );
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

  async getSignatureForRequest(request: HttpRequest, credentials: Credentials) {
    /**
     * A user gets a signature for a request.
     *
     * @param request - Request to send.
     * @param credentials - Credentials for the signature creation.
     * @returns HeaderBag - Headers containing the signature for the request.
     */
    try {
      const signer = new SignatureV4({
        credentials: {
          accessKeyId: credentials.AccessKeyId,
          secretAccessKey: credentials.SecretKey,
          sessionToken: credentials.SessionToken,
        },
        service: 'execute-api',
        region: 'eu-west-2',
        sha256: Sha256,
      });
      const signatureRequest = await signer.sign(request);
      return signatureRequest.headers;
    } catch (err) {
      throw err;
    }
  }

  // async revokeRefreshToken(refreshToken: string): Promise<boolean> {
  //   /**
  //   Revokes all of the access tokens generated by the specified refresh token.
  //   After the token is revoked, the user cannot use the revoked token.
  //   @param refreshToken - Refresh token to be revoked.
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
