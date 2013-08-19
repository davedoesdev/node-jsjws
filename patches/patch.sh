#!/bin/bash
cd "$(dirname "$0")"
for f in *.patch
do
  #patch -l -p1 -d "../$(echo "$f" | sed -r 's/(\.[0-9]+)?\.patch$//')" < "$f"
  here="$PWD"
  (
  cd "../$(echo "$f" | sed -r 's/(\.[0-9]+)?\.patch$//')"
  git apply --ignore-whitespace "$here/$f"
  )
done
