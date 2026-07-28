import { access, copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const serverEntry = fileURLToPath(
  new URL("../dist/server/index.js", import.meta.url),
);
const metadataDirectory = fileURLToPath(
  new URL("../dist/.openai", import.meta.url),
);
const sourceMetadata = fileURLToPath(
  new URL("../.openai/hosting.json", import.meta.url),
);
const deployMetadata = fileURLToPath(
  new URL("../dist/.openai/hosting.json", import.meta.url),
);

await access(serverEntry);
await mkdir(metadataDirectory, { recursive: true });
await copyFile(sourceMetadata, deployMetadata);
