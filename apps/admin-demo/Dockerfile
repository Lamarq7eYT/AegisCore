FROM node:24-bookworm AS build
WORKDIR /workspace
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/admin-demo/package.json apps/admin-demo/package.json
COPY packages ./packages
COPY apps/admin-demo ./apps/admin-demo
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts
RUN pnpm --filter @aegis/admin-demo build

FROM nginx:1.28-alpine
COPY --from=build /workspace/apps/admin-demo/dist /usr/share/nginx/html

