import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5178,
    // The knowledge base lives next to the engine, one directory up. Allow the
    // parent so the dev server can serve a .db without copying it around.
    fs: { allow: [".."] },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});