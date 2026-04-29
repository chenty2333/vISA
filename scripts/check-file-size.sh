#!/usr/bin/env bash
set -euo pipefail

# File size gate for the VMOS workspace.
# Thresholds tighten as the codebase is restructured.
WARN_LINES=1500
FAIL_LINES=5000

# No hard-limit exemptions remain. Keep this list empty unless a transitional
# split must land before the corresponding module can be brought below FAIL_LINES.
KNOWN_LARGE_FILES=()

is_known() {
    local file="$1"
    for known in "${KNOWN_LARGE_FILES[@]}"; do
        if [[ "$file" == *"$known" ]]; then
            return 0
        fi
    done
    return 1
}

violations=0

while IFS= read -r line; do
    lines=$(echo "$line" | awk '{print $1}')
    file=$(echo "$line" | awk '{print $2}')

    # Skip generated files
    if echo "$file" | grep -q 'generated'; then
        continue
    fi

    if [ "$lines" -gt "$FAIL_LINES" ]; then
        if is_known "$file"; then
            echo "KNOWN: $file ($lines lines) — tracked for splitting, not failing"
        else
            echo "FAIL: $file ($lines lines) exceeds hard limit of $FAIL_LINES"
            violations=$((violations + 1))
        fi
    elif [ "$lines" -gt "$WARN_LINES" ]; then
        echo "WARN: $file ($lines lines) exceeds $WARN_LINES — please split into modules"
    fi
done < <(find . -name '*.rs' -not -path './target/*' -not -path './.git/*' -exec wc -l {} + \
    | grep -v ' total$' \
    | sort -rn \
    | awk -v max="$WARN_LINES" '$1 > max {print $1, $2}')

if [ "$violations" -gt 0 ]; then
    echo ""
    echo "$violations file(s) exceed the hard limit. Please split them into modules."
    exit 1
fi

echo "File size check passed."
