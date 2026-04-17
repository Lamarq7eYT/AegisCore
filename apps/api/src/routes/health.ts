import type { FastifyPluginAsync } from "fastify";

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get("/health/live", async () => ({
    ok: true,
    service: "aegis-api",
    ts: new Date().toISOString()
  }));

  app.get("/health/ready", async () => ({
    ok: true,
    storageDriver: app.aegis.config.persistence.storageDriver,
    sessionDriver: app.aegis.config.persistence.sessionDriver,
    nativeFallbackAllowed: app.aegis.config.security.allowNativeFallback
  }));
};

