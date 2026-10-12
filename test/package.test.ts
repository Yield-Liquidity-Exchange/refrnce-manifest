// What a stranger relies on before running anything: the licence is the licence it says it is, the metadata
// names the command and the files that ship, the pinned dependencies are exact, the schema file is the
// envelope schema, and the vendored IDL files are the bytes their provenance note records.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { EnvelopeSchema } from "../src/manifest/types.js";
import { VERSION } from "../src/version.js";
import { makeFixture } from "./helpers/fixture.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8").replace(/\r\n/g, "\n");
const sha256 = (p: string) =>
  createHash("sha256")
    .update(readFileSync(join(ROOT, p)))
    .digest("hex");
const pkg = JSON.parse(read("package.json"));

describe("package.json", () => {
  it("names the package, the licence and the command", () => {
    expect(pkg.name).toBe("trace-manifest-verifier");
    expect(pkg.license).toBe("Apache-2.0");
    expect(pkg.bin).toEqual({ "trace-verify": "dist/cli.js" });
    expect(pkg.type).toBe("module");
    expect(pkg.version).toBe(VERSION);
  });

  it("the build runs the boundary check first, so a stray import fails the build itself", () => {
    expect(pkg.scripts.prebuild).toBe("node tools/check-boundary.mjs");
    expect(pkg.scripts.boundary).toBe("node tools/check-boundary.mjs");
  });

  it("is private, so that publishing to a registry is a deliberate act", () => {
    expect(pkg.private).toBe(true);
  });

  it("ships the build, the schema, the examples and the licence files, and no source of tests", () => {
    expect(pkg.files).toEqual(["dist", "schema", "examples", "LICENSE", "NOTICE", "README.md"]);
  });

  it("pins every dependency, runtime and development, to an exact version", () => {
    for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies }))
      expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("exports the schema file, and the file exists", () => {
    expect(pkg.exports["./schema"]).toBe("./schema/trace-manifest-1.0.schema.json");
    expect(existsSync(join(ROOT, "schema/trace-manifest-1.0.schema.json"))).toBe(true);
  });

  it("the command's entry file starts with a Node shebang", () => {
    expect(read("src/cli.ts").startsWith("#!/usr/bin/env node\n")).toBe(true);
  });
});

describe("licence files", () => {
  it("LICENSE is the unmodified Apache License 2.0 text", () => {
    const text = read("LICENSE");
    expect(text).toContain("Apache License");
    expect(text).toContain("Version 2.0, January 2004");
    expect(text).toContain("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION");
    expect(text).toContain("END OF TERMS AND CONDITIONS");
    // The text as published by the Apache Software Foundation (11357 bytes).
    expect(sha256("LICENSE")).toBe(
      "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    );
  });

  it("NOTICE exists, names the licence and has a copyright line", () => {
    const text = read("NOTICE");
    expect(text).toMatch(/^Trace Manifest Verifier\nCopyright 2026 /);
    expect(text).toContain("Apache License, Version 2.0");
  });
});

describe("the JSON Schema file", () => {
  const schema = JSON.parse(read("schema/trace-manifest-1.0.schema.json"));

  it("describes the envelope, and requires exactly the four envelope fields", () => {
    expect(schema.$ref).toBe("#/definitions/envelope");
    expect(schema.definitions.envelope.required.sort()).toEqual(
      ["anchor", "manifest", "manifest_hash", "signature"].sort(),
    );
    expect(schema.definitions.envelope.additionalProperties).toBe(false);
  });

  it("allows every field of a real envelope and no other (it is strict in the same places the verifier is)", async () => {
    const { envelope } = await makeFixture();
    expect(EnvelopeSchema.safeParse(envelope).success).toBe(true);
    const allowed = Object.keys(schema.definitions.envelope.properties).sort();
    expect(allowed).toEqual(Object.keys(envelope).sort());
    const manifestKeys = Object.keys(schema.definitions.manifest.properties).sort();
    expect(manifestKeys).toEqual(Object.keys(envelope.manifest).sort());
  });

  it("points at files that exist in this package", () => {
    const text = schema.description as string;
    for (const m of text.matchAll(/\((src\/[a-z/.-]+\.ts)\)/g))
      expect(existsSync(join(ROOT, m[1])), m[1]).toBe(true);
  });
});

describe("the vendored IDL files match their provenance note", () => {
  const note = read("src/solana/idl/README.md");
  it.each([
    ["src/solana/idl/jupiter-v6.idl.json", 76690],
    ["src/solana/idl/jupiter-v6-onchain.idl.json", 32453],
  ])("%s", (file, size) => {
    const bytes = readFileSync(join(ROOT, file));
    expect(bytes.length).toBe(size);
    expect(note).toContain(`${size} bytes`);
    expect(note).toContain(sha256(file));
    expect(() => JSON.parse(bytes.toString("utf8"))).not.toThrow();
  });
});
