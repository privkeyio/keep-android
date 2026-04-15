#!/usr/bin/env bash
# Fails CI if any locale's strings.xml is missing a key present in the default
# values/strings.xml (excluding entries marked translatable="false"), or if a
# translated value's printf-style format specifiers do not match the default.
#
# Scope: validates only app/src/main/res/values/strings.xml against its
# BCP-47 locale siblings (values-<lang>[-r<REGION>]/strings.xml). Sibling
# resource files in values/ (strings_settings.xml, strings_main.xml, etc.)
# are currently English-only by design and are NOT checked here. Non-locale
# qualifier directories (values-night, values-w600dp, values-v31, etc.) are
# ignored.
#
# Uses python for XML parsing to avoid fragile regex handling of multi-line
# entries, xliff:g tags, CDATA, etc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RES_DIR="${ROOT}/app/src/main/res"
DEFAULT_FILE="${RES_DIR}/values/strings.xml"

if [[ ! -f "${DEFAULT_FILE}" ]]; then
    echo "Error: default strings file not found at ${DEFAULT_FILE}" >&2
    exit 2
fi

python3 - "${RES_DIR}" "${DEFAULT_FILE}" <<'PY'
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

res_dir, default_file = sys.argv[1], sys.argv[2]

LOCALE_RE = re.compile(r'^values-(?:[a-z]{2,3}(?:-r[A-Z]{2})?|b\+[A-Za-z0-9+]+)$')
FORMAT_RE = re.compile(r'%(?:\d+\$)?[-+ 0#,(]*\d*(?:\.\d+)?[a-zA-Z]')

def entry_specs(el):
    """Return a Counter of printf-style specifiers for an entry.

    For <string>, uses its full text. For <plurals>/<string-array>, returns
    the specifier multiset from a single representative child item: all items
    within a plurals/array are expected to take the same args, and different
    locales have different numbers of plural items (e.g. Japanese has only
    'other'), so aggregating across items would produce false positives.
    """
    tag = el.tag.split('}')[-1]
    if tag == 'string':
        text = ''.join(el.itertext()).replace('%%', '')
        return Counter(FORMAT_RE.findall(text))
    for child in list(el):
        text = ''.join(child.itertext()).replace('%%', '')
        specs = Counter(FORMAT_RE.findall(text))
        if specs:
            return specs
    return Counter()

def load_entries(path):
    """Return (translatable_keys, all_keys, specs) for an XML file.

    specs maps (tag, name) -> Counter of format specifiers for translatable
    entries only.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    translatable = set()
    allkeys = set()
    specs = {}
    for el in list(root):
        tag = el.tag.split('}')[-1]
        if tag not in ('string', 'plurals', 'string-array'):
            continue
        name = el.get('name')
        if not name:
            continue
        allkeys.add((tag, name))
        specs[(tag, name)] = entry_specs(el)
        if el.get('translatable', 'true').lower() == 'false':
            continue
        translatable.add((tag, name))
    return translatable, allkeys, specs

default_translatable, _, default_specs = load_entries(default_file)

errors = []
locales = []
for entry in sorted(os.listdir(res_dir)):
    if not LOCALE_RE.match(entry):
        continue
    path = os.path.join(res_dir, entry, 'strings.xml')
    if not os.path.isfile(path):
        continue
    locales.append(entry)
    try:
        _, locale_all, locale_specs = load_entries(path)
    except ET.ParseError as e:
        errors.append(f"{entry}: XML parse error: {e}")
        continue
    missing = sorted(default_translatable - locale_all)
    if missing:
        for tag, name in missing:
            errors.append(f"{entry}: missing {tag} '{name}'")
    for key, actual in locale_specs.items():
        if key not in default_specs:
            continue
        expected = default_specs[key]
        if expected != actual:
            tag, name = key
            exp_str = ', '.join(sorted(expected.elements())) or '(none)'
            act_str = ', '.join(sorted(actual.elements())) or '(none)'
            errors.append(
                f"{entry}: format specifier mismatch in {tag} '{name}': "
                f"expected [{exp_str}], got [{act_str}]"
            )

if not locales:
    print("No locale-specific strings.xml files found; nothing to check.")
    sys.exit(0)

print(f"Checked {len(locales)} locale(s): {', '.join(locales)}")
print(f"Default file has {len(default_translatable)} translatable entries.")

if errors:
    print("\nLocale drift detected:", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    sys.exit(1)

print("OK: all locales contain every translatable key from the default.")
PY
