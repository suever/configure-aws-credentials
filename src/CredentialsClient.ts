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
    if (props.region !== undefined) {
      this.region = props.region;
    }
    if (props.proxyServer) {
      info('Configuring proxy handler for STS client');
      const proxyOptions: { httpProxy: string; httpsProxy: string; noProxy?: string } = {
        httpProxy: props.proxyServer,
        httpsProxy: props.proxyServer,
      };
      if (props.noProxy !== undefined) {
        proxyOptions.noProxy = props.noProxy;
      }
      const getProxyForUrl = new ProxyResolver(proxyOptions).getProxyForUrl;
      const handler = new ProxyAgent({ getProxyForUrl });
      this.requestHandler = new NodeHttpHandler({
        httpsAgent: handler,
        httpAgent: handler,
      });
    }
  }

  public get stsClient(): STSClient {
    if (!this._stsClient) {
      const config = { customUserAgent: USER_AGENT } as {
        customUserAgent: string;
        region?: string;
        requestHandler?: NodeHttpHandler;
      };
      if (this.region !== undefined) config.region = this.region;
      if (this.requestHandler !== undefined) config.requestHandler = this.requestHandler;
      this._stsClient = new STSClient(config);
    }
    return this._stsClient;
  }

  public async validateCredentials(
    expectedAccessKeyId?: string,
    roleChaining?: boolean,
    expectedAccountIds?: string[],
  ) {
    info('Validating credentials');
    let credentials: AwsCredentialIdentity;
    try {
      info('Loading credentials from SDK');
      credentials = await this.loadCredentials();
      if (!credentials.accessKeyId) {
        throw new Error('Access key ID empty after loading credentials');
      }
      info(`Credentials loaded successfully (AccessKeyId: ${credentials.accessKeyId.substring(0, 4)}...)`);
    } catch (error) {
      info(`Failed to load credentials: ${errorMessage(error)}`);
      throw new Error(`Credentials could not be loaded, please check your action inputs: ${errorMessage(error)}`);
    }
    if (expectedAccountIds && expectedAccountIds.length > 0 && expectedAccountIds[0] !== '') {
      info(`Validating account ID against allowed list: ${expectedAccountIds.join(', ')}`);
      let callerIdentity: Awaited<ReturnType<typeof getCallerIdentity>>;
      try {
        info('Calling GetCallerIdentity for account validation');
        callerIdentity = await getCallerIdentity(this.stsClient);
        info(`GetCallerIdentity returned account: ${callerIdentity.Account}`);
      } catch (error) {
        info(`GetCallerIdentity failed: ${errorMessage(error)}`);
        throw new Error(`Could not validate account ID of credentials: ${errorMessage(error)}`);
      }
      if (!callerIdentity.Account || !expectedAccountIds.includes(callerIdentity.Account)) {
        const errorMsg = `The account ID of the provided credentials (${
          callerIdentity.Account ?? 'unknown'
        }) does not match any of the expected account IDs: ${expectedAccountIds.join(', ')}`;
        info(errorMsg);
        throw new Error(errorMsg);
      }
      info('Account ID validation successful');
    }

    if (!roleChaining) {
      const actualAccessKeyId = credentials.accessKeyId;
      if (expectedAccessKeyId && expectedAccessKeyId !== actualAccessKeyId) {
        const errorMsg = 'Credentials loaded by the SDK do not match the expected access key ID configured by the action';
        info(`Access key validation failed: expected ${expectedAccessKeyId?.substring(0, 4)}..., got ${actualAccessKeyId.substring(0, 4)}...`);
        throw new Error(errorMsg);
      }
    }
    info('Credential validation completed successfully');
  }

  private async loadCredentials() {
    const config = {} as { requestHandler?: NodeHttpHandler };
    if (this.requestHandler !== undefined) config.requestHandler = this.requestHandler;
    const client = new STSClient(config);
    return client.config.credentials();
  }
}
