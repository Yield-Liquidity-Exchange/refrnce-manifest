// Entity labels are not part of the open package.
//
// In the issuer's own tooling a small read-only registry names addresses the issuer has confirmed, and the
// normaliser turns an entry into an Attributed ENTITY_LABEL claim. That registry is not published. This file
// has the same exports with NOTHING registered, so the normaliser here emits no entity label claims.
//
// Verification is not affected: a record may carry ENTITY_LABEL claims, and the verifier lists every
// Attributed claim as not independently checked and never compares it with anything.
// Pure and isomorphic: no network, no Node-only imports.

import { readOnlyMap } from "./readonly-map.js";

/** Empty: this package has no registry. */
export const ENTITY_REGISTRY_VERSION = "";

/** Empty: no entity label claim is ever emitted here. */
export const ENTITY_LABEL_SOURCE = "";

/** Address to label. Empty and read-only. */
export const ENTITY_LABELS: ReadonlyMap<string, string> = readOnlyMap<string, string>([]);

/** The label for a registered address: always undefined here, there are none. */
export function entityLabel(address: string): string | undefined {
  return ENTITY_LABELS.get(address);
}
