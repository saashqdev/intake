# inTake

Intake is a self-hosted platform for deploying and managing applications,
similar to Vercel, Railway, or Heroku. inTake provides automated deployment
workflows, container orchestration, and infrastructure management capabilities
while giving you full control over your infrastructure and data.

## 🚀 Self-Hosting inTake with Docker Compose

This guide walks you through setting up and running your own self-hosted
instance of inTake, a powerful workflow management platform, using Docker
Compose and Tailscale.

### ✅ Prerequisites

- Docker
- Tailscale account
- Domain
- Server (recommended 2VPC, 8GB RAM)

### 🧭 Setup Instructions

#### 1. Clone the repository

```bash
git clone https://github.com/saashqdev/intake/
cd intake
```

#### 2. Tailscale Setup

1. Login to [tailscale](https://tailscale.com) and go to the Admin Console.
2. Update Access controls
   ```json
   {
     "tagOwners": {
       "tag:customer-machine": ["autogroup:admin"],
       "tag:intake-proxy": ["autogroup:admin"],
       "tag:intake-support": ["autogroup:admin"]
     },
     "grants": [
       {
         "src": ["autogroup:admin"],
         "dst": ["tag:customer-machine"],
         "ip": ["*"]
       },
       {
         "src": ["tag:intake-proxy"],
         "dst": ["tag:customer-machine"],
         "ip": ["*"]
       },
       {
         "src": ["tag:intake-support"],
         "dst": ["tag:customer-machine"],
         "ip": ["*"]
       }
     ],
     "ssh": [
       {
         "action": "accept",
         "src": ["autogroup:admin", "tag:intake-support"],
         "dst": ["tag:customer-machine"],
         "users": ["autogroup:admin", "root"]
       }
     ]
   }
   ```
3. Create Keys
   1. Go to settings.
   2. Navigate to Personal Settings > Keys
      1. Generate reusable auth key.
   3. Navigate to Tailnet Settings > OAuth clients
      1. Generate OAuth client key with all read permissions and write
         permission for `auth keys` with `customer-machine` tag.

#### 3. DNS Configuration

Setup DNS records with your provider:

```
  Type: A,
  Name: *.up
  Value: <your-server-ip>
  Proxy: OFF
```

#### 4. Configure Environment Variables

Create .env file & add the required variables.

```
# mongodb
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=password
MONGO_DB_NAME=inTake

# redis
REDIS_URI="redis://redis:6379"

# config-generator
WILD_CARD_DOMAIN=up.example.com
JWT_TOKEN=your-jwt-token
PROXY_PORT=9999

# inTake app
NEXT_PUBLIC_WEBSITE_URL=intake.up.example.com
DATABASE_URI=mongodb://${MONGO_INITDB_ROOT_USERNAME}:${MONGO_INITDB_ROOT_PASSWORD}@mongodb:27017/${MONGO_DB_NAME}?authSource=admin
PAYLOAD_SECRET=your-secret

NEXT_PUBLIC_PROXY_DOMAIN_URL=up.example.com
NEXT_PUBLIC_PROXY_CNAME=cname.up.example.com

# tailscale
TAILSCALE_AUTH_KEY=tskey-auth-xxxx
TAILSCALE_OAUTH_CLIENT_SECRET=tskey-client-xxxx
TAILSCALE_TAILNET=your-tailnet-name

# (Optional variables) Better stack - For telemetry
NEXT_PUBLIC_BETTER_STACK_SOURCE_TOKEN=bstk-xxx
NEXT_PUBLIC_BETTER_STACK_INGESTING_URL=https://logs.betterstack.com

# (Optional variables) resend - For email configurations
RESEND_API_KEY=re_12345
RESEND_SENDER_EMAIL=no-reply@up.example.com
RESEND_SENDER_NAME=inTake System
```

#### 5. Traefik Setup

1. Create `traefik.yaml` file at the root directory.
2. Change the email

   ```yaml
   entryPoints:
     web:
       address: ':80'
     websecure:
       address: ':443'

   providers:
     file:
       directory: /etc/traefik/dynamic
       watch: true

   certificatesResolvers:
     letsencrypt:
       acme:
         email: johndoe@example.com
         storage: /etc/traefik/acme.json
         httpChallenge:
           entryPoint: web # Used for app-specific domains

   api:
     dashboard: false
     insecure: false # ⚠️ Secure this in production

   log:
     level: INFO
   ```

3. Create and secure `acme.json`:

   ```bash
   touch acme.json
   chmod 600 acme.json
   ```

4. create `dynamic/intake-app.yaml` file

```yaml
http:
  routers:
    intake-app-router:
      rule: Host(`intake.up.example.com`)
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: intake-app-service
  services:
    intake-app-service:
      loadBalancer:
        servers:
          - url: http://payload-app:3000
```

5. create `dynamic/intake-traefik.yaml` file

```yaml
http:
  routers:
    intake-traefik-router:
      rule: Host(`intake-traefik.up.example.com`)
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: intake-traefik-service
  services:
    intake-traefik-service:
      loadBalancer:
        servers:
          - url: http://config-generator:9999
```

6. create `dynamic/intake-beszel.yaml` file

```yaml
http:
  routers:
    intake-beszel-router:
      rule: Host(`monitoring.up.example.com`)
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: intake-beszel-service
  services:
    intake-beszel-service:
      loadBalancer:
        servers:
          - url: http://beszel:8090
```

#### 6. Start the Docker Compose Stack

```bash
source .env
docker compose --env-file .env up -d
```

## 🤝 Contributors

<a href="https://github.com/akhil-naidu/dflow/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=akhil-naidu/dflow" />
</a>
