#!/usr/bin/env sh

XCADDY_SKIP_BUILD=1 xcaddy build --with github.com/mohammed90/caddy-ngrok-listener@latest
mv buildenv* caddy-build