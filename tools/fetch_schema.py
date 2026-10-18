"""Regenerate tests/schema/ocsf-1.9.0-pruned.json from schema.ocsf.io.

Run manually when bumping the OCSF version. The output is committed so tests
never touch the network.
"""

import json
import pathlib
import urllib.request

VERSION = "1.9.0"
PROFILES = "security_control,host,ai_operation"
EXPORT_URL = f"https://schema.ocsf.io/export/schema?profiles={PROFILES}"
KEEP = [
    "file_activity",
    "process_activity",
    "http_activity",
    "api_activity",
    "application_lifecycle",
    "detection_finding",
]
OUT = pathlib.Path(__file__).parent.parent / "tests" / "schema" / f"ocsf-{VERSION}-pruned.json"


def object_refs(attributes):
    return {
        a["object_type"]
        for a in attributes.values()
        if a.get("type") == "object_t" and "object_type" in a
    }


def main():
    with urllib.request.urlopen(EXPORT_URL) as response:
        schema = json.load(response)
    if schema["version"] != VERSION:
        raise SystemExit(f"expected OCSF {VERSION}, server returned {schema['version']}")

    objects = schema["objects"]
    reached, queue = set(), set()
    for name in KEEP:
        queue |= object_refs(schema["classes"][name]["attributes"])
    while queue:
        name = queue.pop()
        if name in reached or name not in objects:
            continue
        reached.add(name)
        queue |= object_refs(objects[name].get("attributes", {}))

    pruned = {
        "version": schema["version"],
        "classes": {name: schema["classes"][name] for name in KEEP},
        "objects": {name: objects[name] for name in sorted(reached)},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(pruned, indent=1, sort_keys=True))
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(reached)} objects)")


if __name__ == "__main__":
    main()
