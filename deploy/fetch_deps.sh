#!/bin/bash
# Download the two dependencies next to server.c: STC's coroutine header and
# llhttp (the release branch, which contains the generated C sources).
set -e
cd "$(dirname "$0")/.."
mkdir -p stc
[ -f stc/coroutine.h ] || curl -sSfLo stc/coroutine.h \
    https://raw.githubusercontent.com/stclib/stcsingle/main/stc/coroutine.h
[ -d llhttp ] || git clone -q --depth 1 --branch release https://github.com/nodejs/llhttp.git
echo "dependencies ready: stc/coroutine.h, llhttp/"
