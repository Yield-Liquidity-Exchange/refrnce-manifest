// Unit tests run in plain node and make no network calls: the RPC is always a fake.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
    // A few tests start a child process or compile the package; give them room on a loaded machine.
    testTimeout: 30_000,
  },
});
