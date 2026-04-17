import type { FastifyPluginAsync } from "fastify";

export const protectedRoutes: FastifyPluginAsync = async (app) => {
  app.get(
    "/protected/users/:userId/profile",
    {
      config: {
        security: {
          auth: true,
          csrf: false,
          resource: "profile",
          action: "read",
          permissions: ["profile:read:any"],
          allowSelf: true,
          ownerParam: "userId"
        }
      }
    },
    async (request, reply) => {
      const params = request.params as { userId: string };
      const user = await app.aegis.persistence.findUserById(params.userId);
      if (!user) {
        return reply.code(404).send({ error: "user-not-found" });
      }

      return {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roles: user.roles,
          permissions: user.permissions,
          mfaEnabled: user.mfaEnabled
        }
      };
    }
  );
};

