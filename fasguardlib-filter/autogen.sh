#!/bin/sh
cd "${0%/*}" || exit 1
exec autoreconf -fviW all
