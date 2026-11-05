# The "Try Mandu" container: what "Open in GitHub Codespaces" on the README
# starts (devcontainer.json; docs/design/distribution/packaging.md §3.1).
#
# Node and the published @mandusec/mandu, nothing else: `mandu demo` runs the
# real components offline against a stand-in AI, with no API key and no login.
# The package is installed when the image is built, so the container is
# ready when it opens. Mandu needs no root: the container runs as the image's
# `node` user, with Docker's default seccomp profile and capabilities.
#
# The Node pin is the one scripts/install.sh downloads (NODE_PIN), at or above
# Mandu's floor; launcher/test/unit/devcontainer.test.ts checks both.
FROM node:22.22.1-bookworm

# `latest` by default, so a new codespace gets the current release;
# --build-arg MANDU_VERSION=<version> pins one.
ARG MANDU_VERSION=latest

# The full bookworm image already has what the demo's later steps run (curl,
# openssl) and git. The package has no install scripts and no native npm
# dependencies; its prebuilt native helpers ship inside it.
RUN NPM_CONFIG_UPDATE_NOTIFIER=false npm install -g "@mandusec/mandu@${MANDU_VERSION}" \
    && npm cache clean --force \
    && mandu --version

USER node
WORKDIR /home/node
