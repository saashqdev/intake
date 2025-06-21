# inTake

Intake is a self-hosted platform for deploying and managing applications,
similar to Vercel, Railway, or Heroku. inTake provides automated deployment
workflows, container orchestration, and infrastructure management capabilities
while giving you full control over your infrastructure and data.

## Self Hosting

### Docker

You can deploy inTake as docker-image on your server, follow this guide👇

#### Requirements

1. git
2. docker
3. postgres
4. redis

#### Process

1. clone intake

```bash
git clone https://github.com/saashqdev/intake intake
```

2. change into directory

```bash
cd intake
```

3. create a postgres instance

- create postgres instance on [Railway](https://railway.com/dashboard) or
  [ContentQL](https://contentql.io/dashboard/create-new-project) and copy the
  url
- or run postgres docker-image

```bash
# pull the postgres docker image
docker pull postgres

# run postgres with a attached volume & exposing port so we can connect locally
# change the username, password by changing POSTGRES_USER, POSTGRES_PASSWORD as per your need
docker run -d \
  -v pgdata:/var/lib/postgresql/data \
  -p 5432:5432 \
  --name my-postgres \
  -e POSTGRES_USER=admin \
  -e POSTGRES_PASSWORD=secretpassword \
  postgres
```

4. create a redis instance

- create redis instance on [Railway](https://railway.com/dashboard) or
  [ContentQL](https://contentql.io/dashboard/create-new-project) and copy the
  url
- or run redis docker-image

> Note: Upstash is not recommended as we're using redis pub/sub & message queues

```bash
# pull the redis docker image
docker pull redis

# run redis with a attached volume & exposing port so we can connect locally
# change password as per your need using the --requirepass flag
docker run -d \
  -v redis-data:/data \
  -p 6379:6379 \
  --name my-redis \
  redis redis-server --requirepass your-password
```

5. trigger docker-image build

> Note: we use PAYLOAD_SECRET to encrypt fields in database, make sure you don't
> lose it.

> Note: NEXT_PUBLIC_WEBSITE_URL should be in this format -> ✅ `mydomain.com`.
> don't use this format ❌ `https://mydomain.com/`

```bash
# pass the postgres, redis database-url's as build-arguments
# replace NEXT_PUBLIC_WEBSITE_URL with your domain
docker build \
  --build-arg DATABASE_URI="postgres://postgres:password@localhost:5432/intake" \
  --build-arg REDIS_URI="redis://:password@localhost:6379" \
  --build-arg PAYLOAD_SECRET="1781c9a00336ffa7fdf27ce7" \
  --build-arg NEXT_PUBLIC_WEBSITE_URL="localhost:3000" \
  -t intake .
```

4. Run the docker-image

```bash
# pass the postgres, redis database-url's as environment variables
# replace NEXT_PUBLIC_WEBSITE_URL with your domain
docker run -d -p 3000:3000 \
  -e DATABASE_URI="postgres://postgres:password@localhost:5432/intake" \
  -e REDIS_URI="redis://:password@localhost:6379" \
  -e PAYLOAD_SECRET="1781c9a00336ffa7fdf27ce7"
  -e NEXT_PUBLIC_WEBSITE_URL="localhost:3000"
  intake
```
