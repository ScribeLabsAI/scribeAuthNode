import { CognitoIdentityProvider as CognitoIdentityServiceProvider } from '@aws-sdk/client-cognito-identity-provider';
import AWS from 'aws-sdk';

AWS.config.update({ region: 'eu-west-2' });

class UnauthorizedExceptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedExceptionError';
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
      const responseInitiate = await this.client.initiateAuth({
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          USERNAME: username,
          PASSWORD: password,
        },
        ClientMetadata: {
          newPassword,
        },
      });
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
        } catch {
          throw new TooManyRequestsError(
            'Password has been changed too many times. Try again later'
          );
        }
      }
    } catch {
      throw new UnauthorizedExceptionError('Username and/or Password are incorrect');
    }
  }
}

export { ScribeAuth };
