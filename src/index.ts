// The public surface of the package. Everything else is internal and may change.
//
//   const rpc = createResilientRpc({ cluster: "mainnet-beta" });
//   const result = await verifyEnvelope(envelope, { rpc, cluster: "mainnet-beta", rawText });
//   result.verdict; // "verified" | "does_not_match" | "unable_to_check"

export {
  CHECK_IDS,
  CHECK_NAMES,
  DEV_KEY_PREFIX,
  MEMO_PREFIX,
  isDevKeyId,
  verdictOf,
  verifyEnvelope,
} from "./manifest/verify/core.js";
export type {
  CheckEvidence,
  CheckId,
  CheckResult,
  CheckStatus,
  RegistryLookup,
  RegistryRecord,
  Verdict,
  VerifyFile,
  VerifyOptions,
  VerifyResult,
} from "./manifest/verify/core.js";
export type {
  ClaimCheck,
  ClaimStatus,
  RederiveResult,
  TransactionRead,
} from "./manifest/verify/rederive.js";
export type { RpcEndpointUse } from "./manifest/verify/rpc-sources.js";
export { IssuerKeysSchema, parseIssuerKeys } from "./manifest/verify/signature.js";
export type { IssuerKey, IssuerKeys } from "./manifest/verify/signature.js";

export { canonicalizeJcs } from "./manifest/canonical.js";
export { hashManifest } from "./manifest/hash.js";
export { hashArtifact } from "./manifest/artifact-hash.js";
export { checkManifestRules, detectDuplicateKeys } from "./manifest/manifest-rules.js";
export { CLAIM_RULES, assertClaimAllowed } from "./manifest/claim-rules.js";
export { FORMULAS, recompute } from "./manifest/formulas.js";
export {
  ClaimSchema,
  EnvelopeSchema,
  MANIFEST_CLUSTERS,
  MANIFEST_SCHEMA_ID,
  ManifestSchema,
} from "./manifest/types.js";
export type { Claim, Envelope, Manifest, ManifestCluster } from "./manifest/types.js";

export { normaliseSolanaTransaction, NORMALISER_ID } from "./solana/normalise.js";
export { REGISTRY_VERSION } from "./solana/programs.js";
export {
  RPC_ENDPOINTS,
  RpcConfigError,
  RpcError,
  RpcNotFoundError,
  checkUserEndpoint,
  createResilientRpc,
  createSolanaRpc,
} from "./solana/rpc.js";
export type { ResilientSolanaRpc, SolanaCluster, SolanaRpc } from "./solana/rpc.js";
