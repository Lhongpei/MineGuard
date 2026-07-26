import { rename, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const outputDirectory = fileURLToPath(new URL("../out", import.meta.url));
const deployDirectory = fileURLToPath(new URL("../dist", import.meta.url));

await rm(deployDirectory, { recursive: true, force: true });
await rename(outputDirectory, deployDirectory);
