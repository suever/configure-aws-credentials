import * as core from '@actions/core';
import type { Credentials, STSClient } from '@aws-sdk/client-sts';
import { GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import type { CredentialsClient } from './CredentialsClient';

const MAX_TAG_VALUE_LENGTH = 256;
const SANITIZATION_CHARACTER = '_';
const SPECIAL_CHARS_REGEX = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]+/;

export function translateEnvVariables() {
  const envVars = [
    'AWS_REGION',
    'ROLE_TO_ASSUME',
    'WEB_IDENTITY_TOKEN_FILE',
    'ROLE_CHAINING',
    'AUDIENCE',
    'HTTP_PROXY',
    'MASK_AWS_ACCOUNT_ID',
    'ROLE_DURATION_SECONDS',
    'ROLE_EXTERNAL_ID',
    'ROLE_SESSION_NAME',
    'ROLE_SKIP_SESSION_TAGGING',
    'INLINE_SESSION_POLICY',
    'MANAGED_SESSION_POLICIES',
    'OUTPUT_CREDENTIALS',
    'UNSET_CURRENT_CREDENTIALS',
    'DISABLE_RETRY',
    'RETRY_MAX_ATTEMPTS',
    'SPECIAL_CHARACTERS_WORKAROUND',
    'USE_EXISTING_CREDENTIALS',
    'NO_PROXY',
  ];
  // Treat HTTPS_PROXY as HTTP_PROXY. Precedence is HTTPS_PROXY > HTTP_PROXY
  if (process.env.HTTPS_PROXY) process.env.HTTP_PROXY = process.env.HTTPS_PROXY;

  for (const envVar of envVars) {
    if (process.env[envVar]) {
      const inputKey = `INPUT_${envVar.replace(/_/g, '-')}`;
      process.env[inputKey] = process.env[inputKey] || process.env[envVar];
    }
  }
}

// Configure the AWS CLI and AWS SDKs using environment variables and set them as secrets.
// Setting the credentials as secrets masks them in Github Actions logs
export function exportCredentials(
  creds?: Partial<Credentials>,
  outputCredentials?: boolean,
  outputEnvCredentials?: boolean,
) {
  if (creds?.AccessKeyId) {
    core.setSecret(creds.AccessKeyId);
  }

  if (creds?.SecretAccessKey) {
    core.setSecret(creds.SecretAccessKey);
  }

  if (creds?.SessionToken) {
    core.setSecret(creds.SessionToken);
  }

  if (outputEnvCredentials) {
    if (creds?.AccessKeyId) {
      core.exportVariable('AWS_ACCESS_KEY_ID', creds.AccessKeyId);
    }

    if (creds?.SecretAccessKey) {
      core.exportVariable('AWS_SECRET_ACCESS_KEY', creds.SecretAccessKey);
    }

    if (creds?.SessionToken) {
      core.exportVariable('AWS_SESSION_TOKEN', creds.SessionToken);
    } else if (process.env.AWS_SESSION_TOKEN) {
      // clear session token from previous credentials action
      core.exportVariable('AWS_SESSION_TOKEN', '');
    }
  }

  if (outputCredentials) {
    if (creds?.AccessKeyId) {
      core.setOutput('aws-access-key-id', creds.AccessKeyId);
    }
    if (creds?.SecretAccessKey) {
      core.setOutput('aws-secret-access-key', creds.SecretAccessKey);
    }
    if (creds?.SessionToken) {
      core.setOutput('aws-session-token', creds.SessionToken);
    }
    if (creds?.Expiration) {
      core.setOutput('aws-expiration', creds.Expiration);
    }
  }
}

export function unsetCredentials(outputEnvCredentials?: boolean) {
  if (outputEnvCredentials) {
    core.exportVariable('AWS_ACCESS_KEY_ID', '');
    core.exportVariable('AWS_SECRET_ACCESS_KEY', '');
    core.exportVariable('AWS_SESSION_TOKEN', '');
    core.exportVariable('AWS_REGION', '');
    core.exportVariable('AWS_DEFAULT_REGION', '');
  }
}

export function exportRegion(region: string, outputEnvCredentials?: boolean) {
  core.info(`[exportRegion] Called with region=${region}, outputEnvCredentials=${outputEnvCredentials}`);
  if (outputEnvCredentials) {
    core.info('[exportRegion] Exporting AWS_DEFAULT_REGION and AWS_REGION environment variables');
    core.exportVariable('AWS_DEFAULT_REGION', region);
    core.exportVariable('AWS_REGION', region);
    core.info('[exportRegion] Environment variables exported successfully');
  } else {
    core.info('[exportRegion] Skipping environment variable export (outputEnvCredentials is false)');
  }
}

export async function getCallerIdentity(client: STSClient): Promise<{ Account: string; Arn: string; UserId?: string }> {
  core.info('[getCallerIdentity] Sending GetCallerIdentityCommand to STS');
  const identity = await client.send(new GetCallerIdentityCommand({}));
  core.info(`[getCallerIdentity] Received response - Account: ${identity.Account}, Arn: ${identity.Arn}, UserId: ${identity.UserId}`);
  if (!identity.Account || !identity.Arn) {
    core.error('[getCallerIdentity] Response missing Account or ARN');
    throw new Error('Could not get Account ID or ARN from STS. Did you set credentials?');
  }
  const result: { Account: string; Arn: string; UserId?: string } = {
    Account: identity.Account,
    Arn: identity.Arn,
  };
  if (identity.UserId !== undefined) {
    result.UserId = identity.UserId;
  }
  core.info(`[getCallerIdentity] Returning result: ${JSON.stringify(result)}`);
  return result;
}

// Obtains account ID from STS Client and sets it as output
// If providedAccountId is provided, uses it directly without making an STS call
export async function exportAccountId(
  credentialsClient: CredentialsClient,
  maskAccountId?: boolean,
  providedAccountId?: string,
) {
  core.info(`[exportAccountId] Called with maskAccountId=${maskAccountId}, providedAccountId=${providedAccountId || 'not provided'}`);
  let accountId: string;
  let arn: string | undefined;

  if (providedAccountId) {
    // Use the provided account ID directly
    accountId = providedAccountId;
    core.info(`[exportAccountId] Using provided AWS account ID: ${accountId}`);
  } else {
    // Make STS call to retrieve account ID
    core.info('[exportAccountId] No account ID provided, calling GetCallerIdentity to retrieve it');
    try {
      const identity = await getCallerIdentity(credentialsClient.stsClient);
      accountId = identity.Account;
      arn = identity.Arn;
      core.info(`[exportAccountId] GetCallerIdentity successful - Account: ${accountId}, ARN: ${arn}`);
    } catch (error) {
      core.error(`[exportAccountId] GetCallerIdentity failed: ${errorMessage(error)}`);
      throw error;
    }
  }

  if (maskAccountId) {
    core.info('[exportAccountId] Masking account ID and ARN as secrets');
    core.setSecret(accountId);
    if (arn) {
      core.setSecret(arn);
    }
    core.info('[exportAccountId] Secrets masked successfully');
  } else {
    core.info('[exportAccountId] Not masking account ID (maskAccountId is false)');
  }
  core.info(`[exportAccountId] Setting output: aws-account-id=${accountId}`);
  core.setOutput('aws-account-id', accountId);
  if (arn) {
    core.info(`[exportAccountId] Setting output: authenticated-arn=${arn}`);
    core.setOutput('authenticated-arn', arn);
  } else {
    core.info('[exportAccountId] No ARN available to set as output');
  }
  core.info(`[exportAccountId] Returning account ID: ${accountId}`);
  return accountId;
}

// Tags have a more restrictive set of acceptable characters than GitHub environment variables can.
// This replaces anything not conforming to the tag restrictions by inverting the regular expression.
// See the AWS documentation for constraint specifics https://docs.aws.amazon.com/STS/latest/APIReference/API_Tag.html.
export function sanitizeGitHubVariables(name: string) {
  const nameWithoutSpecialCharacters = name.replace(/[^\p{L}\p{Z}\p{N}_.:/=+\-@]/gu, SANITIZATION_CHARACTER);
  const nameTruncated = nameWithoutSpecialCharacters.slice(0, MAX_TAG_VALUE_LENGTH);
  return nameTruncated;
}

export async function defaultSleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
let sleep = defaultSleep;

export function withsleep(s: typeof sleep) {
  sleep = s;
}

export function reset() {
  sleep = defaultSleep;
}

export function verifyKeys(creds: Partial<Credentials> | undefined) {
  if (!creds) {
    return false;
  }
  if (creds.AccessKeyId) {
    if (SPECIAL_CHARS_REGEX.test(creds.AccessKeyId)) {
      core.debug('AccessKeyId contains special characters.');
      return false;
    }
  }
  if (creds.SecretAccessKey) {
    if (SPECIAL_CHARS_REGEX.test(creds.SecretAccessKey)) {
      core.debug('SecretAccessKey contains special characters.');
      return false;
    }
  }
  return true;
}

// Retries the promise with exponential backoff if the error isRetryable up to maxRetries time.
export async function retryAndBackoff<T>(
  fn: () => Promise<T>,
  isRetryable: boolean,
  maxRetries = 12,
  retries = 0,
  base = 50,
): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (!isRetryable) {
      core.debug(`retryAndBackoff: error is not retryable: ${errorMessage(err)}`);
      throw err;
    }
    // It's retryable, so sleep and retry.
    const delay = Math.random() * (2 ** retries * base);
    const nextRetry = retries + 1;

    core.debug(
      `retryAndBackoff: attempt ${nextRetry} of ${maxRetries} failed: ${errorMessage(err)}. ` +
        `Retrying after ${Math.floor(delay)}ms.`,
    );

    await sleep(delay);

    if (nextRetry >= maxRetries) {
      core.debug('retryAndBackoff: reached max retries; giving up.');
      throw err;
    }

    return await retryAndBackoff(fn, isRetryable, maxRetries, nextRetry, base);
  }
}

/* c8 ignore start */
export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export function isDefined<T>(i: T | undefined | null): i is T {
  return i !== undefined && i !== null;
}
/* c8 ignore stop */

export async function areCredentialsValid(credentialsClient: CredentialsClient) {
  core.info('[areCredentialsValid] Checking if existing credentials are valid');
  const client = credentialsClient.stsClient;
  try {
    core.info('[areCredentialsValid] Sending GetCallerIdentityCommand');
    const identity = await client.send(new GetCallerIdentityCommand({}));
    core.info(`[areCredentialsValid] Response received - Account: ${identity.Account}`);
    if (identity.Account) {
      core.info('[areCredentialsValid] Credentials are valid');
      return true;
    }
    core.info('[areCredentialsValid] No account ID in response, credentials invalid');
    return false;
  } catch (error) {
    core.info(`[areCredentialsValid] GetCallerIdentity failed: ${errorMessage(error)} - credentials invalid`);
    return false;
  }
}

/**
 * Like core.getBooleanInput, but respects the required option.
 *
 * From https://github.com/actions/toolkit/blob/6876e2a664ec02908178087905b9155e9892a437/packages/core/src/core.ts
 *
 * Gets the input value of the boolean type in the YAML 1.2 "core schema" specification.
 * Support boolean input list: `true | True | TRUE | false | False | FALSE` .
 * The return value is also in boolean type.
 * ref: https://yaml.org/spec/1.2/spec.html#id2804923
 *
 * @param     name     name of the input to get
 * @param     options  optional. See core.InputOptions. Also supports optional 'default' if the input is not set
 * @returns   boolean
 */
export function getBooleanInput(name: string, options?: core.InputOptions & { default?: boolean }): boolean {
  const trueValue = ['true', 'True', 'TRUE'];
  const falseValue = ['false', 'False', 'FALSE'];
  const optionsWithoutDefault = { ...options };
  delete optionsWithoutDefault.default;
  const val = core.getInput(name, optionsWithoutDefault);
  if (trueValue.includes(val)) return true;
  if (falseValue.includes(val)) return false;
  if (val === '') return options?.default ?? false;
  throw new TypeError(
    `Input does not meet YAML 1.2 "Core Schema" specification: ${name}\n` +
      `Support boolean input list: \`true | True | TRUE | false | False | FALSE\``,
  );
}
