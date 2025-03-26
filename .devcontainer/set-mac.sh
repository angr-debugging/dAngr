#!/bin/bash

# replace Dockerfile.dev with Dockerfile.mac.dev in .devcontainer/devcontainer.json
sed -i 's/Dockerfile.dev/Dockerfile.mac.dev/g' .devcontainer/devcontainer.json