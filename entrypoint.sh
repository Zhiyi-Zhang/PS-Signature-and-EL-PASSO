#! /bin/sh -l

echo "update submodule"
git submodule update --init --recursive

echo "compile MCL"
make mcl

echo "build the codebase"
make

echo "run test files"
OUTPUT=$(make check 2>&1)

echo "::set-output name=test-log::$OUTPUT"