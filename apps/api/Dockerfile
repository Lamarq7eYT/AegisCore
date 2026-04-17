FROM node:24-bookworm AS deps
WORKDIR /workspace
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/api/package.json apps/api/package.json
COPY packages ./packages
COPY native ./native
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts

FROM deps AS build
WORKDIR /workspace
COPY . .
RUN corepack enable && pnpm run prisma:generate && pnpm --filter @aegis/api build

FROM node:24-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build /workspace/node_modules ./node_modules
COPY --from=build /workspace/apps/api/dist ./apps/api/dist
COPY --from=build /workspace/apps/api/prisma ./apps/api/prisma
COPY --from=build /workspace/package.json ./package.json
ENV NODE_ENV=production
CMD ["node", "apps/api/dist/server.js"]

