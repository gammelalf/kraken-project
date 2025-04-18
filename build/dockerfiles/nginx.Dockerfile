FROM node:23-bookworm-slim AS build-frontend

WORKDIR /app

COPY ./kraken_frontend/package.json .
COPY ./kraken_frontend/yarn.lock .
COPY ./kraken_frontend/ .

RUN --mount=type=cache,target=./node_modules/ \
    <<EOF
set -e
yarn --frozen-lockfile
yarn build
mv ./dist /frontend
EOF


FROM nginx:latest AS final

COPY --from=build-frontend /frontend /usr/share/nginx/html/frontend