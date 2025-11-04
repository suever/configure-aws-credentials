import * as core from '@actions/core';
import type { AssumeRoleCommandOutput } from '@aws-sdk/client-sts';
import { assumeRole } from './assumeRole';
import { CredentialsClient } from './CredentialsClient';
import {
  areCredentialsValid,
  errorMessage,
  exportAccountId,
  exportCredentials,
  exportRegion,
  getBooleanInput,
  retryAndBackoff,
  translateEnvVariables,
  unsetCredentials,
  verifyKeys,
} from './helpers';

const DEFAULT_ROLE_DURATION = 3600; // One hour (seconds)
const ROLE_SESSION_NAME = 'GitHubActions';
const REGION_REGEX = /^[a-z0-9-]+$/g;

export async function run() {
  try {
    translateEnvVariables();
    core.info('=== Starting configure-aws-credentials action ===');

    // Get inputs
    // Undefined inputs are empty strings ( or empty arrays)
    const AccessKeyId = core.getInput('aws-access-key-id', { required: false });
    const SecretAccessKey = core.getInput('aws-secret-access-key', { required: false });
    const sessionTokenInput = core.getInput('aws-session-token', { required: false });
    const SessionToken = sessionTokenInput === '' ? undefined : sessionTokenInput;
    const region = core.getInput('aws-region', { required: true });
    const accountIdInput = core.getInput('aws-account-id', { required: false });
    const providedAccountId = accountIdInput === '' ? undefined : accountIdInput;
    const roleToAssume = core.getInput('role-to-assume', { required: false });
    const audience = core.getInput('audience', { required: false });
    const maskAccountId = getBooleanInput('mask-aws-account-id', { required: false });
    const roleExternalId = core.getInput('role-external-id', { required: false });
    const webIdentityTokenFile = core.getInput('web-identity-token-file', { required: false });
    const roleDuration =
      Number.parseInt(core.getInput('role-duration-seconds', { required: false })) || DEFAULT_ROLE_DURATION;
    const roleSessionName = core.getInput('role-session-name', { required: false }) || ROLE_SESSION_NAME;
    const roleSkipSessionTagging = getBooleanInput('role-skip-session-tagging', { required: false });
    const proxyServer = core.getInput('http-proxy', { required: false }) || process.env.HTTP_PROXY;
    const inlineSessionPolicy = core.getInput('inline-session-policy', { required: false });
    const managedSessionPolicies = core.getMultilineInput('managed-session-policies', { required: false }).map((p) => {
      return { arn: p };
    });
    const roleChaining = getBooleanInput('role-chaining', { required: false });
    const outputCredentials = getBooleanInput('output-credentials', { required: false });
    const outputEnvCredentials = getBooleanInput('output-env-credentials', { required: false, default: true });
    const unsetCurrentCredentials = getBooleanInput('unset-current-credentials', { required: false });
    let disableRetry = getBooleanInput('disable-retry', { required: false });
    const specialCharacterWorkaround = getBooleanInput('special-characters-workaround', { required: false });
    const useExistingCredentials = core.getInput('use-existing-credentials', { required: false });
    let maxRetries = Number.parseInt(core.getInput('retry-max-attempts', { required: false })) || 12;
    const expectedAccountIds = core
      .getInput('allowed-account-ids', { required: false })
      .split(',')
      .map((s) => s.trim());
    const forceSkipOidc = getBooleanInput('force-skip-oidc', { required: false });
    const skipCredentialValidation = getBooleanInput('skip-credential-validation', { required: false });
    const noProxy = core.getInput('no-proxy', { required: false });
    const globalTimeout = Number.parseInt(core.getInput('action-timeout-s', { required: false })) || 0;

    // Log all inputs (except sensitive ones)
    core.info(`Input: aws-region=${region}`);
    core.info(`Input: aws-account-id=${providedAccountId || 'not provided'}`);
    core.info(`Input: role-to-assume=${roleToAssume || 'not provided'}`);
    core.info(`Input: role-chaining=${roleChaining}`);
    core.info(`Input: role-duration-seconds=${roleDuration}`);
    core.info(`Input: role-session-name=${roleSessionName}`);
    core.info(`Input: role-skip-session-tagging=${roleSkipSessionTagging}`);
    core.info(`Input: audience=${audience || 'not provided'}`);
    core.info(`Input: web-identity-token-file=${webIdentityTokenFile || 'not provided'}`);
    core.info(`Input: mask-aws-account-id=${maskAccountId}`);
    core.info(`Input: output-credentials=${outputCredentials}`);
    core.info(`Input: output-env-credentials=${outputEnvCredentials}`);
    core.info(`Input: unset-current-credentials=${unsetCurrentCredentials}`);
    core.info(`Input: disable-retry=${disableRetry}`);
    core.info(`Input: retry-max-attempts=${maxRetries}`);
    core.info(`Input: special-characters-workaround=${specialCharacterWorkaround}`);
    core.info(`Input: use-existing-credentials=${useExistingCredentials || 'not provided'}`);
    core.info(`Input: allowed-account-ids=${expectedAccountIds.filter(id => id !== '').join(', ') || 'not provided'}`);
    core.info(`Input: force-skip-oidc=${forceSkipOidc}`);
    core.info(`Input: skip-credential-validation=${skipCredentialValidation}`);
    core.info(`Input: http-proxy=${proxyServer ? 'configured' : 'not configured'}`);
    core.info(`Input: no-proxy=${noProxy || 'not provided'}`);
    core.info(`Input: action-timeout-s=${globalTimeout}`);
    core.info(`Input: aws-access-key-id=${AccessKeyId ? 'provided' : 'not provided'}`);
    core.info(`Input: aws-secret-access-key=${SecretAccessKey ? 'provided' : 'not provided'}`);
    core.info(`Input: aws-session-token=${SessionToken ? 'provided' : 'not provided'}`);

    let timeoutId: NodeJS.Timeout | undefined;
    if (globalTimeout > 0) {
      core.info(`Setting a global timeout of ${globalTimeout} seconds for the action`);
      timeoutId = setTimeout(() => {
        core.setFailed(`Action timed out after ${globalTimeout} seconds`);
        process.exit(1);
      }, globalTimeout * 1000);
    }

    core.info('=== Validating Input Configuration ===');
    if (forceSkipOidc && roleToAssume && !AccessKeyId && !webIdentityTokenFile) {
      core.error('Invalid configuration: force-skip-oidc requires aws-access-key-id or web-identity-token-file');
      throw new Error(
        "If 'force-skip-oidc' is true and 'role-to-assume' is set, 'aws-access-key-id' or 'web-identity-token-file' must be set",
      );
    }
    core.info('Input configuration validation passed');

    if (specialCharacterWorkaround) {
      // 😳
      core.info('Special character workaround enabled, forcing retry settings');
      disableRetry = false;
      maxRetries = 12;
      core.info(`Updated retry settings: disableRetry=${disableRetry}, maxRetries=${maxRetries}`);
    } else if (maxRetries < 1) {
      core.info('maxRetries was less than 1, setting to 1');
      maxRetries = 1;
    }

    // Logic to decide whether to attempt to use OIDC or not
    core.info('=== Determining Authentication Method ===');
    const useGitHubOIDCProvider = () => {
      core.info('Evaluating whether to use GitHub OIDC provider...');
      if (forceSkipOidc) {
        core.info('force-skip-oidc is true, skipping OIDC');
        return false;
      }
      // The `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variable is set when the `id-token` permission is granted.
      // This is necessary to authenticate with OIDC, but not strictly set just for OIDC. If it is not set and all other
      // checks pass, it is likely but not guaranteed that the user needs but lacks this permission in their workflow.
      // So, we will log a warning when it is the only piece absent
      core.info(`OIDC evaluation - roleToAssume: ${!!roleToAssume}, webIdentityTokenFile: ${!!webIdentityTokenFile}, AccessKeyId: ${!!AccessKeyId}, ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${!!process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}, roleChaining: ${!!roleChaining}`);
      if (
        !!roleToAssume &&
        !webIdentityTokenFile &&
        !AccessKeyId &&
        !process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN &&
        !roleChaining
      ) {
        core.info(
          'It looks like you might be trying to authenticate with OIDC. Did you mean to set the `id-token` permission? ' +
            'If you are not trying to authenticate with OIDC and the action is working successfully, you can ignore this message.',
        );
      }
      const willUseOIDC = (
        !!roleToAssume &&
        !!process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN &&
        !AccessKeyId &&
        !webIdentityTokenFile &&
        !roleChaining
      );
      core.info(`Will use GitHub OIDC provider: ${willUseOIDC}`);
      return willUseOIDC;
    };

    if (unsetCurrentCredentials) {
      core.info('=== Unsetting Current Credentials ===');
      core.info(`Calling unsetCredentials with outputEnvCredentials=${outputEnvCredentials}`);
      unsetCredentials(outputEnvCredentials);
      core.info('Current credentials unset');
    }

    core.info('=== Validating and Exporting Region ===');
    core.info(`Validating region: ${region}`);
    if (!region.match(REGION_REGEX)) {
      core.error(`Region validation failed: ${region} does not match ${REGION_REGEX}`);
      throw new Error(`Region is not valid: ${region}`);
    }
    core.info('Region validation passed');
    core.info(`Exporting region with outputEnvCredentials=${outputEnvCredentials}`);
    exportRegion(region, outputEnvCredentials);
    core.info('Region exported');

    // Instantiate credentials client
    core.info('=== Instantiating Credentials Client ===');
    const clientProps: { region: string; proxyServer?: string; noProxy?: string } = { region };
    if (proxyServer) {
      core.info(`Adding proxy server to client props: ${proxyServer ? 'configured' : 'none'}`);
      clientProps.proxyServer = proxyServer;
    }
    if (noProxy) {
      core.info(`Adding no-proxy configuration: ${noProxy}`);
      clientProps.noProxy = noProxy;
    }
    core.info(`Creating CredentialsClient with region=${clientProps.region}, proxyServer=${clientProps.proxyServer || 'none'}, noProxy=${clientProps.noProxy || 'none'}`);
    const credentialsClient = new CredentialsClient(clientProps);
    core.info('CredentialsClient instantiated successfully');
    let sourceAccountId: string | undefined;
    let webIdentityToken: string;

    //if the user wants to attempt to use existing credentials, check if we have some already
    if (useExistingCredentials) {
      core.info('=== Checking for Existing Valid Credentials ===');
      core.info('use-existing-credentials is set, checking if credentials are already valid');
      const validCredentials = await areCredentialsValid(credentialsClient);
      core.info(`Existing credentials valid: ${validCredentials}`);
      if (validCredentials) {
        core.notice('Pre-existing credentials are valid. No need to generate new ones.');
        if (timeoutId) clearTimeout(timeoutId);
        core.info('Exiting early due to valid existing credentials');
        return;
      }
      core.notice('No valid credentials exist. Running as normal.');
    }

    // If OIDC is being used, generate token
    // Else, export credentials provided as input
    core.info('=== Setting Up Authentication Credentials ===');
    if (useGitHubOIDCProvider()) {
      core.info('Using GitHub OIDC provider to get ID token');
      core.info(`Audience: ${audience}`);
      core.info(`Retry enabled: ${!disableRetry}, Max retries: ${maxRetries}`);
      try {
        webIdentityToken = await retryAndBackoff(
          async () => {
            core.info('Calling core.getIDToken()...');
            return core.getIDToken(audience);
          },
          !disableRetry,
          maxRetries,
        );
        core.info('Successfully obtained ID token from GitHub OIDC');
      } catch (error) {
        core.error(`getIDToken call failed: ${errorMessage(error)}`);
        throw new Error(`getIDToken call failed: ${errorMessage(error)}`);
      }
    } else if (AccessKeyId) {
      core.info('Using provided AWS access key ID and secret access key');
      if (!SecretAccessKey) {
        core.error('aws-access-key-id was provided but aws-secret-access-key is missing');
        throw new Error("'aws-secret-access-key' must be provided if 'aws-access-key-id' is provided");
      }
      // The STS client for calling AssumeRole pulls creds from the environment.
      // Plus, in the assume role case, if the AssumeRole call fails, we want
      // the source credentials to already be masked as secrets
      // in any error messages.
      core.info(`Exporting credentials - outputCredentials=${outputCredentials}, outputEnvCredentials=${outputEnvCredentials}`);
      exportCredentials({ AccessKeyId, SecretAccessKey, SessionToken }, outputCredentials, outputEnvCredentials);
      core.info('Credentials exported successfully');
    } else if (!webIdentityTokenFile && !roleChaining) {
      core.info('Using ambient credentials (no AccessKeyId, no webIdentityTokenFile, no roleChaining)');
      // Proceed only if credentials can be picked up
      core.info('Validating credentials (no AccessKeyId, no webIdentityTokenFile, no roleChaining)');
      if (!skipCredentialValidation) {
        core.info('Running validateCredentials()');
        try {
          await credentialsClient.validateCredentials(undefined, roleChaining, expectedAccountIds);
          core.info('Credential validation successful');
        } catch (error) {
          core.error(`Credential validation failed: ${errorMessage(error)}`);
          throw error;
        }
      } else {
        core.info('Skipping credential validation due to skip-credential-validation flag');
      }
      core.info('Exporting account ID');
      sourceAccountId = await exportAccountId(credentialsClient, maskAccountId, providedAccountId);
      core.info(`Account ID exported: ${sourceAccountId}`);
    }

    if (AccessKeyId || roleChaining) {
      // Validate that the SDK can actually pick up credentials.
      // This validates cases where this action is using existing environment credentials,
      // and cases where the user intended to provide input credentials but the secrets inputs resolved to empty strings.
      core.info(`Validating credentials (AccessKeyId=${AccessKeyId ? 'provided' : 'not provided'}, roleChaining=${roleChaining})`);
      if (!skipCredentialValidation) {
        core.info('Running validateCredentials()');
        try {
          await credentialsClient.validateCredentials(AccessKeyId, roleChaining, expectedAccountIds);
          core.info('Credential validation successful');
        } catch (error) {
          core.error(`Credential validation failed: ${errorMessage(error)}`);
          throw error;
        }
      } else {
        core.info('Skipping credential validation due to skip-credential-validation flag');
      }
      core.info('Exporting account ID');
      sourceAccountId = await exportAccountId(credentialsClient, maskAccountId, providedAccountId);
      core.info(`Account ID exported: ${sourceAccountId}`);
    }

    // Get role credentials if configured to do so
    if (roleToAssume) {
      core.info(`Attempting to assume role: ${roleToAssume}`);
      let roleCredentials: AssumeRoleCommandOutput;
      do {
        try {
          roleCredentials = await retryAndBackoff(
            async () => {
              core.info('Calling assumeRole()');
              return assumeRole({
                credentialsClient,
                sourceAccountId,
                roleToAssume,
                roleExternalId,
                roleDuration,
                roleSessionName,
                roleSkipSessionTagging,
                webIdentityTokenFile,
                webIdentityToken,
                inlineSessionPolicy,
                managedSessionPolicies,
              });
            },
            !disableRetry,
            maxRetries,
          );
          core.info('AssumeRole successful');
        } catch (error) {
          core.error(`AssumeRole failed: ${errorMessage(error)}`);
          core.error(`Role: ${roleToAssume}`);
          core.error(`Source Account ID: ${sourceAccountId || 'undefined'}`);
          core.error(`Role Duration: ${roleDuration}`);
          core.error(`Role Session Name: ${roleSessionName}`);
          throw error;
        }
      } while (specialCharacterWorkaround && !verifyKeys(roleCredentials.Credentials));
      core.info(`Authenticated as assumedRoleId ${roleCredentials.AssumedRoleUser?.AssumedRoleId}`);
      exportCredentials(roleCredentials.Credentials, outputCredentials, outputEnvCredentials);
      // We need to validate the credentials in 2 of our use-cases
      // First: self-hosted runners. If the GITHUB_ACTIONS environment variable
      //  is set to `true` then we are NOT in a self-hosted runner.
      // Second: Customer provided credentials manually (IAM User keys stored in GH Secrets)
      const shouldValidate = !skipCredentialValidation && (!process.env.GITHUB_ACTIONS || AccessKeyId);
      core.info(`Should validate assumed role credentials: ${shouldValidate} (skipCredentialValidation=${skipCredentialValidation}, GITHUB_ACTIONS=${process.env.GITHUB_ACTIONS}, AccessKeyId=${AccessKeyId ? 'provided' : 'not provided'})`);
      if (shouldValidate) {
        core.info('Running validateCredentials() for assumed role');
        try {
          await credentialsClient.validateCredentials(
            roleCredentials.Credentials?.AccessKeyId,
            roleChaining,
            expectedAccountIds,
          );
          core.info('Assumed role credential validation successful');
        } catch (error) {
          core.error(`Assumed role credential validation failed: ${errorMessage(error)}`);
          throw error;
        }
      } else {
        core.info('Skipping assumed role credential validation');
      }
      if (outputEnvCredentials) {
        core.info('Exporting account ID for assumed role');
        await exportAccountId(credentialsClient, maskAccountId, providedAccountId);
      }
    } else {
      core.info('Proceeding with IAM user credentials');
    }

    // Clear timeout on successful completion
    if (timeoutId) clearTimeout(timeoutId);
  } catch (error) {
    core.setFailed(errorMessage(error));

    const showStackTrace = process.env.SHOW_STACK_TRACE;
    if (showStackTrace === 'true') {
      throw error;
    }
  }
}

/* c8 ignore start */
/* istanbul ignore next */
if (require.main === module) {
  (async () => {
    await run();
  })().catch((error) => {
    core.setFailed(errorMessage(error));
  });
}
