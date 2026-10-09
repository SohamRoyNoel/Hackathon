import { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';

/**
 * Shared Amazon Bedrock configuration + client factory.
 *
 * Both the privilege-escalation agent (the "brain") and the security judge use
 * the same model/region/credentials, so resolve them in one place.
 */

export interface BedrockConfig {
  modelId: string;
  region: string;
  bearerToken?: string;
}

export function resolveBedrockConfig(
  overrides: Partial<BedrockConfig> = {},
): BedrockConfig {
  const bearerToken =
    overrides.bearerToken ??
    process.env.AWS_BEARER_TOKEN_BEDROCK ??
    process.env.AWS_BEDROCK_BEARER_TOKEN;

  // The AWS SDK reads a Bedrock API key from AWS_BEARER_TOKEN_BEDROCK; our env
  // uses AWS_BEDROCK_BEARER_TOKEN, so mirror it for downstream SDK auto-detect.
  if (bearerToken && !process.env.AWS_BEARER_TOKEN_BEDROCK) {
    process.env.AWS_BEARER_TOKEN_BEDROCK = bearerToken;
  }

  return {
    modelId:
      overrides.modelId ??
      process.env.ANTHROPIC_MODEL ??
      'global.anthropic.claude-opus-4-8',
    region: overrides.region ?? process.env.AWS_REGION ?? 'us-east-1',
    bearerToken,
  };
}

export function createBedrockClient(cfg: BedrockConfig): BedrockRuntimeClient {
  return new BedrockRuntimeClient({
    region: cfg.region,
    maxAttempts: 5,
    retryMode: 'adaptive',
    // Explicit bearer-token (Bedrock API key) identity provider so we don't
    // rely solely on env auto-detection.
    ...(cfg.bearerToken
      ? { token: async () => ({ token: cfg.bearerToken! }) }
      : {}),
  });
}
