import { loadConfig } from "@aegis/config";
import { createApp } from "./index.js";

const config = loadConfig();
const app = await createApp({ config });

try {
  await app.listen({
    host: config.server.host,
    port: config.server.port
  });
  app.log.info(
    {
      host: config.server.host,
      port: config.server.port
    },
    "Aegis API listening."
  );
} catch (error) {
  app.log.error({ err: error }, "Failed to start Aegis API.");
  process.exit(1);
}

