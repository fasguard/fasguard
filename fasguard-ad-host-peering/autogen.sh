#!/bin/sh
mydir=${0%/*}
cd "${mydir}" || exit 1
exec autoreconf -fviW all
