import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseSecurityArtifact } from "@aegis/security-core-ts";
import { evaluateUpload } from "@aegis/upload-guard";
import type { FastifyPluginAsync } from "fastify";
import { buildUploadRecord } from "../lib/persistence.js";

export const uploadRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    "/uploads",
    {
      config: {
        security: {
          auth: true,
          sensitive: true,
          resource: "upload",
          action: "create",
          permissions: ["uploads:create"]
        }
      }
    },
    async (request, reply) => {
      const routePath = request.routeOptions.url ?? request.url;
      if (!request.principal) {
        return reply.code(401).send({ error: "auth-required" });
      }

      const part = await request.file();
      if (!part) {
        return reply.code(400).send({ error: "missing-file" });
      }

      const content = await part.toBuffer();
      const verdict = evaluateUpload({
        filename: part.filename,
        declaredMime: part.mimetype,
        content,
        maxBytes: app.aegis.config.security.maxUploadBytes
      });

      const artifact = parseSecurityArtifact(
        {
          filename: part.filename,
          mimeType: part.mimetype,
          origin: request.headers.origin as string | undefined,
          contentLength: content.byteLength
        },
        { allowFallback: app.aegis.config.security.allowNativeFallback }
      );

      if (!verdict.accepted) {
        await app.aegis.audit.recordSecurityEvent({
          kind: "upload.rejected",
          severity: "high",
          correlationId: request.correlationId,
          route: routePath,
          actorId: request.principal.userId,
          sessionId: request.session?.id ?? null,
          ipHash: request.session?.ipHash ?? null,
          riskScore: request.securityContext.riskScore.score,
          findings: request.securityContext.findings,
          metadata: { verdict, artifact }
        });
        return reply.code(400).send({ verdict, artifact });
      }

      const quarantineDir = path.resolve(process.cwd(), "apps/api/uploads/quarantine");
      await mkdir(quarantineDir, { recursive: true });
      const storedName = `${Date.now()}_${verdict.normalizedFilename}`;
      await writeFile(path.join(quarantineDir, storedName), content);

      const record = buildUploadRecord({
        ownerId: request.principal.userId,
        originalName: part.filename,
        verdict
      });
      await app.aegis.persistence.saveUpload({
        ...record,
        storedName
      });

      await app.aegis.audit.recordAudit({
        actorId: request.principal.userId,
        action: "upload.create",
        targetType: "upload",
        targetId: record.id,
        decision: "allow",
        reason: "Upload accepted into quarantine.",
        correlationId: request.correlationId,
        metadata: { verdict, artifact, storedName }
      });

      return {
        verdict,
        artifact,
        storedName
      };
    }
  );
};
