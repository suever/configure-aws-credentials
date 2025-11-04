import { info } from '@actions/core';
import { STSClient } from '@aws-sdk/client-sts';
import type { AwsCredentialIdentity } from '@aws-sdk/types';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { ProxyAgent } from 'proxy-agent';
import { errorMessage, getCallerIdentity } from './helpers';
import { ProxyResolver } from './ProxyResolver';

const USER_AGENT = 'configure-aws-credentials-for-github-actions';

export interface CredentialsClientProps {
  region?: string;
  proxyServer?: string;
  noProxy?: string;
}

export class CredentialsClient {
  public region?: string;
  private _stsClient?: STSClient;
  private readonly requestHandler?: NodeHttpHandler;

  constructor(props: CredentialsClientProps) {
    info('[CredentialsClient.constructor] Initializing CredentialsClient');
    info(`[CredentialsClient.constructor] Props: region=${props.region}, proxyServer=${props.proxyServer || 'none'}, noProxy=${props.noProxy || 'none'}`);
    if (props.region !== undefined) {
      this.region = props.region;
      info(`[CredentialsClient.constructor] Region set to: ${this.region}`);
    }
    if (props.proxyServer) {
      info('[CredentialsClient.constructor] Configuring proxy handler for STS client');
      const proxyOptions: { httpProxy: string; httpsProxy: string; noProxy?: string } = {
        httpProxy: props.proxyServer,
        httpsProxy: props.proxyServer,
      };
      if (props.noProxy !== undefined) {
        proxyOptions.noProxy = props.noProxy;
        info(`[CredentialsClient.constructor] No-proxy configuration: ${props.noProxy}`);
      }
      info(`[CredentialsClient.constructor] Creating ProxyResolver with options: ${JSON.stringify(proxyOptions)}`);
      const getProxyForUrl = new ProxyResolver(proxyOptions).getProxyForUrl;
      const handler = new ProxyAgent({ getProxyForUrl });
      this.requestHandler = new NodeHttpHandler({
        httpsAgent: handler,
        httpAgent: handler,
      });
      info('[CredentialsClient.constructor] Proxy handler configured successfully');
    }
    info('[CredentialsClient.constructor] CredentialsClient initialized');
  }

  public get stsClient(): STSClient {
    if (!this._stsClient) {
      info('[CredentialsClient.stsClient] Creating new STSClient');
      const config = { customUserAgent: USER_AGENT } as {
        customUserAgent: string;
        region?: string;
        requestHandler?: NodeHttpHandler;
      };
      if (this.region !== undefined) {
        config.region = this.region;
        info(`[CredentialsClient.stsClient] Setting region: ${this.region}`);
      }
      if (this.requestHandler !== undefined) {
        config.requestHandler = this.requestHandler;
        info('[CredentialsClient.stsClient] Using custom request handler (proxy configured)');
      }
      info(`[CredentialsClient.stsClient] STSClient config: ${JSON.stringify({ customUserAgent: config.customUserAgent, region: config.region, hasRequestHandler: !!config.requestHandler })}`);
      this._stsClient = new STSClient(config);
      info('[CredentialsClient.stsClient] STSClient created successfully');
    } else {
      info('[CredentialsClient.stsClient] Returning existing STSClient instance');
    }
    return this._stsClient;
  }

  public async validateCredentials(
    expectedAccessKeyId?: string,
    roleChaining?: boolean,
    expectedAccountIds?: string[],
  ) {
    info('[CredentialsClient.validateCredentials] ====== Starting Credential Validation ======');
    info(`[CredentialsClient.validateCredentials] Parameters: expectedAccessKeyId=${expectedAccessKeyId ? expectedAccessKeyId.substring(0, 4) + '...' : 'none'}, roleChaining=${roleChaining}, expectedAccountIds=${expectedAccountIds?.join(', ') || 'none'}`);
    let credentials: AwsCredentialIdentity;
    try {
      info('[CredentialsClient.validateCredentials] Loading credentials from AWS SDK');
      credentials = await this.loadCredentials();
      info(`[CredentialsClient.validateCredentials] Credentials loaded from SDK`);
      if (!credentials.accessKeyId) {
        info('[CredentialsClient.validateCredentials] ERROR: Access key ID is empty after loading credentials');
        throw new Error('Access key ID empty after loading credentials');
      }
      info(`[CredentialsClient.validateCredentials] Credentials loaded successfully (AccessKeyId: ${credentials.accessKeyId.substring(0, 4)}...)`);
    } catch (error) {
      info(`[CredentialsClient.validateCredentials] ERROR: Failed to load credentials: ${errorMessage(error)}`);
      throw new Error(`Credentials could not be loaded, please check your action inputs: ${errorMessage(error)}`);
    }
    if (expectedAccountIds && expectedAccountIds.length > 0 && expectedAccountIds[0] !== '') {
      info(`[CredentialsClient.validateCredentials] Account ID validation required. Allowed accounts: ${expectedAccountIds.join(', ')}`);
      let callerIdentity: Awaited<ReturnType<typeof getCallerIdentity>>;
      try {
        info('[CredentialsClient.validateCredentials] Calling GetCallerIdentity for account validation');
        callerIdentity = await getCallerIdentity(this.stsClient);
        info(`[CredentialsClient.validateCredentials] GetCallerIdentity returned account: ${callerIdentity.Account}, ARN: ${callerIdentity.Arn}`);
      } catch (error) {
        info(`[CredentialsClient.validateCredentials] ERROR: GetCallerIdentity failed: ${errorMessage(error)}`);
        throw new Error(`Could not validate account ID of credentials: ${errorMessage(error)}`);
      }
      if (!callerIdentity.Account || !expectedAccountIds.includes(callerIdentity.Account)) {
        const errorMsg = `The account ID of the provided credentials (${
          callerIdentity.Account ?? 'unknown'
        }) does not match any of the expected account IDs: ${expectedAccountIds.join(', ')}`;
        info(`[CredentialsClient.validateCredentials] ERROR: ${errorMsg}`);
        throw new Error(errorMsg);
      }
      info('[CredentialsClient.validateCredentials] Account ID validation successful - account is in allowed list');
    } else {
      info('[CredentialsClient.validateCredentials] No account ID validation required (expectedAccountIds is empty or not provided)');
    }

    if (!roleChaining) {
      info('[CredentialsClient.validateCredentials] Role chaining is false, validating access key ID');
      const actualAccessKeyId = credentials.accessKeyId;
      if (expectedAccessKeyId && expectedAccessKeyId !== actualAccessKeyId) {
        const errorMsg = 'Credentials loaded by the SDK do not match the expected access key ID configured by the action';
        info(`[CredentialsClient.validateCredentials] ERROR: Access key validation failed: expected ${expectedAccessKeyId?.substring(0, 4)}..., got ${actualAccessKeyId.substring(0, 4)}...`);
        throw new Error(errorMsg);
      }
      info('[CredentialsClient.validateCredentials] Access key ID validation successful');
    } else {
      info('[CredentialsClient.validateCredentials] Role chaining is true, skipping access key ID validation');
    }
    info('[CredentialsClient.validateCredentials] ====== Credential Validation Completed Successfully ======');
  }

  private async loadCredentials() {
    info('[CredentialsClient.loadCredentials] Loading credentials from AWS SDK');
    const config = {} as { requestHandler?: NodeHttpHandler };
    if (this.requestHandler !== undefined) {
      config.requestHandler = this.requestHandler;
      info('[CredentialsClient.loadCredentials] Using custom request handler');
    }
    info('[CredentialsClient.loadCredentials] Creating temporary STSClient for credential loading');
    const client = new STSClient(config);
    info('[CredentialsClient.loadCredentials] Calling client.config.credentials()');
    const creds = await client.config.credentials();
    info(`[CredentialsClient.loadCredentials] Credentials loaded - AccessKeyId: ${creds.accessKeyId?.substring(0, 4)}..., hasSessionToken: ${!!creds.sessionToken}`);
    return creds;
  }
}
