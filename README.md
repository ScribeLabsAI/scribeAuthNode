# Scribe Auth Node

Most calls to Scribe's API require authentication and authorization. This library simplifies this process.

You first need a Scribe account and a client ID. Both can be requested at support[atsign]scribelabs[dotsign]ai or through Intercom on https://platform.scribelabs.ai if you already have a Scribe account.

This library interacts directly with our authentication provider [AWS Cognito](https://aws.amazon.com/cognito/) meaning that your username and password never transit through our servers.

## Installation

Add the dependency to your package.json and save it:

```
"dependencies": {
	"@scribelabsai/auth": ">=1.0.0"
}
```

Install it from command line:

```
npm install
```

## Requirements

This library requires Node.js >= 16.20.0

## Methods

### 1. Changing password

```javascript
import { Auth, Tokens } from '@scribelabsai/auth';
const access = new Auth(clientId);
access.changePassword('username', 'password', 'newPassword');
```

### 2. Recovering an account in case of forgotten password

```javascript
import { Auth, Tokens } from '@scribelabsai/auth';
const access = new Auth(clientId);
access.forgotPassword('username', 'password', 'confirmationCode');
```

### 3. Get or generate tokens

##### With username and password

```javascript
import { Auth, Tokens } from '@scribelabsai/auth';
const access = new Auth(clientId);
access.getTokens({ username: 'username', password: 'password' });
```

##### With refresh token

```javascript
import { Auth, Tokens } from '@scribelabsai/auth';
const access = new Auth(clientId);
access.getTokens({ refreshToken: 'refreshToken' });
```

### 4. Revoking a refresh token

#### Disclaimer: revokeToken(refreshToken) is not ready yet, you may use our [Python lib](https://github.com/ScribeLabsAI/ScribeAuth) or call AWS services directly.

## Flow

- If you never have accessed your Scribe account, it probably still contains the temporary password we generated for you. You can change it directly on the [platform](https://platform.scribelabs.ai) or with the `changePassword` method. You won't be able to access anything else until the temporary password has been changed.

- Once the account is up and running, you can request new tokens with `getTokens`. You will initially have to provide your username and password. The access and id tokens are valid for up to 30 minutes. The refresh token is valid for 30 days.

- While you have a valid refresh token, you can request fresh access and id tokens with `getTokens` but using the refresh token this time, so you're not sending your username and password over the wire anymore.

---

To flag an issue, open a ticket on [Github](https://github.com/ScribeLabsAI/ScribeAuthNode/issues) and contact us on Intercom through the platform.
