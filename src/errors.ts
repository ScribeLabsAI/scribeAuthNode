export class UnauthorizedError extends Error {
  /**
  Exception raised when a user cannot perform an action.
  Possible reasons:
  Username and/or Password are incorrect.
  Refresh token is incorrect.
  */
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'UnauthorizedError';
    this.cause = cause;
  }
}

export class TooManyRequestsError extends Error {
  /**
  Exception raised when an action is performed by a user too many times in a short period.
  Actions that could raise this exception:
  Changing a password.
  Revoking a refresh token.
  */
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'TooManyRequestsError';
    this.cause = cause;
  }
}

export class UnknownError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnknownError';
  }
}

export class MissingIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MissingIdError';
  }
}
