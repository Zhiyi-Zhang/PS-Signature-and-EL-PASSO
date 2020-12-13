#! /bin/bash

# If this is not a GitHub Workflow build, then fetch the codebase with git clone
if [ ! -d "/github" ]
then
  git clone https://github.com/Zhiyi-Zhang/PS-Signature-and-EL-PASSO.git
  cd PS-Signature-and-EL-PASSO
fi

echo "update submodule"
git submodule update --init --recursive

echo "compile MCL"
make mcl

echo "build the codebase"
make

echo "run test files"
OUTPUT=$(make check 2>&1)

echo "::set-output name=test-log::$OUTPUT"