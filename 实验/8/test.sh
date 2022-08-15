#!/bin/bash
src=$1
out=${src//.c/}
gcc "$src" -o "$out"
./"$out"
rm "$out"