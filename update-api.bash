#!/bin/bash

if [[ -z "$GTAD" || -z "$CSAPIDIR" ]]; then
    echo "You have to specify GTAD and CSAPIDIR variables."
    exit 1
fi

scriptDir="$(dirname "$(realpath "$0")")"
cd "$scriptDir/src/api" &&
"$GTAD" --config "$scriptDir/gtad/gtad.yaml" --out csapi "$CSAPIDIR" key_backup.yaml-
