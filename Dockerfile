# To use this Dockerfile, you have to set `output: 'standalone'` in your next.config.mjs file.
# From https://github.com/vercel/next.js/blob/canary/examples/with-docker/Dockerfile

FROM node:22.12.0-alpine AS base

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json yarn.lock* package-lock.json* pnpm-lock.yaml* ./
RUN \
  if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  elif [ -f pnpm-lock.yaml ]; then npm install -g corepack@latest && corepack enable && corepack prepare pnpm@10.2.0 --activate && pnpm i --frozen-lockfile; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry during the build.
# ENV NEXT_TELEMETRY_DISABLED 1
ARG NEXT_PUBLIC_WEBSITE_URL
ARG DATABASE_URI
ARG REDIS_URI
ARG PAYLOAD_SECRET
ARG TAILSCALE_AUTH_KEY
ARG TAILSCALE_OAUTH_CLIENT_SECRET
ARG TAILSCALE_TAILNET
ARG NEXT_PUBLIC_PROXY_DOMAIN_URL
ARG NEXT_PUBLIC_BETTER_STACK_SOURCE_TOKEN
ARG NEXT_PUBLIC_BETTER_STACK_INGESTING_URL
ARG RESEND_API_KEY
ARG RESEND_SENDER_EMAIL
ARG RESEND_SENDER_NAME
ARG NEXT_PUBLIC_PROXY_CNAME
ARG NEXT_PUBLIC_DISCORD_INVITE_URL
ARG SKIP_VALIDATION

ENV NEXT_PUBLIC_WEBSITE_URL=$NEXT_PUBLIC_WEBSITE_URL
ENV DATABASE_URI=$DATABASE_URI
ENV REDIS_URI=$REDIS_URI
ENV PAYLOAD_SECRET=$PAYLOAD_SECRET
ENV TAILSCALE_AUTH_KEY=$TAILSCALE_AUTH_KEY
ENV TAILSCALE_OAUTH_CLIENT_SECRET=$TAILSCALE_OAUTH_CLIENT_SECRET
ENV TAILSCALE_TAILNET=$TAILSCALE_TAILNET
ENV NEXT_PUBLIC_PROXY_DOMAIN_URL=$NEXT_PUBLIC_PROXY_DOMAIN_URL
ENV NEXT_PUBLIC_BETTER_STACK_SOURCE_TOKEN=$NEXT_PUBLIC_BETTER_STACK_SOURCE_TOKEN
ENV NEXT_PUBLIC_BETTER_STACK_INGESTING_URL=$NEXT_PUBLIC_BETTER_STACK_INGESTING_URL
ENV RESEND_API_KEY=$RESEND_API_KEY
ENV RESEND_SENDER_EMAIL=$RESEND_SENDER_EMAIL
ENV RESEND_SENDER_NAME=$RESEND_SENDER_NAME
ENV NEXT_PUBLIC_PROXY_CNAME=$NEXT_PUBLIC_PROXY_CNAME
ENV NEXT_PUBLIC_DISCORD_INVITE_URL=$NEXT_PUBLIC_DISCORD_INVITE_URL
ENV SKIP_VALIDATION=$SKIP_VALIDATION

RUN \
  if [ -f yarn.lock ]; then yarn run build; \
  elif [ -f package-lock.json ]; then npm run build; \
  elif [ -f pnpm-lock.yaml ]; then corepack enable && COREPACK_INTEGRITY_KEYS=0 corepack prepare pnpm@10.2.0 --activate && pnpm run build; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
# Uncomment the following line in case you want to disable telemetry during runtime.
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

RUN apk add --no-cache openssh-client

# RUN mkdir -p /var/run/tailscale /var/lib/tailscale && chmod 777 /var/run/tailscale /var/lib/tailscale

RUN apk add --no-cache tailscale

COPY --from=builder /app/public ./public

# Automatically leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER root

EXPOSE 3000

ENV PORT=3000

# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/config/next-config-js/output
ENV HOSTNAME="0.0.0.0"
# CMD ["node", "server.js"]
# CMD ["/app/entrypoint.sh", "Hello World"]
# ENTRYPOINT ["/app/entrypoint.sh"]
ENTRYPOINT ["/bin/sh", "-c", "/app/entrypoint.sh \"$TAILSCALE_AUTH_KEY\""]
