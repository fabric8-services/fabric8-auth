#!/bin/bash
set -e
GHORG=${GHORG:-fabric8-services}
GHREPO=${GHREPO:-fabric8-wit}
cat <<EOF
# About
This description was generated using this script:
\`\`\`sh
`cat $0`
\`\`\`
Invoked as:

    `echo GHORG=${GHORG} GHREPO=${GHREPO} $(basename $0) ${@:1}`

# Changes
EOF
git log \
  --pretty="%n**Commit:** https://github.com/${GHORG}/${GHREPO}/commit/%H%n**Author:** %an (%ae)%n**Date:** %aI%n%n%s%n%n%b%n%n----%n" \
  --reverse ${@:1} \
  | sed -E "s/([\s|\(| ])#([0-9]+)/\1${GHORG}\/${GHREPO}#\2/g"
