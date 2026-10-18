"""Offline OCSF event validator backed by the committed pruned schema.

Mirrors the checks the schema.ocsf.io validation endpoint performs: required
attributes, unknown attributes, profile gating, at_least_one constraints, enum
membership, and the type_uid identity. The one server check not reproduced here
is the observables[].name attribute-path check; the network test covers it.
"""

import functools
import json
import pathlib

SCHEMA_PATH = pathlib.Path(__file__).parent / "schema" / "ocsf-1.9.0-pruned.json"


@functools.lru_cache(maxsize=1)
def schema():
    return json.loads(SCHEMA_PATH.read_text())


@functools.lru_cache(maxsize=1)
def _classes_by_uid():
    return {cls["uid"]: cls for cls in schema()["classes"].values()}


def validate(event):
    """Return human-readable error strings. An empty list means the event is valid."""
    cls = _classes_by_uid().get(event.get("class_uid"))
    if cls is None:
        return [f"unknown class_uid {event.get('class_uid')!r}"]

    errors = []
    profiles = set((event.get("metadata") or {}).get("profiles") or [])

    if event.get("category_uid") != cls["category_uid"]:
        errors.append(
            f"category_uid {event.get('category_uid')!r} != {cls['category_uid']} for {cls['name']}"
        )
    expected_type_uid = cls["uid"] * 100 + (event.get("activity_id") or 0)
    if event.get("type_uid") != expected_type_uid:
        errors.append(
            f"type_uid {event.get('type_uid')!r} != class_uid * 100 + activity_id ({expected_type_uid})"
        )

    _check_attributes(event, cls["attributes"], profiles, cls["name"], errors)
    return errors


def _check_attributes(node, attributes, profiles, path, errors):
    for key, value in node.items():
        spec = attributes.get(key)
        if spec is None:
            errors.append(f"{path}.{key}: unknown attribute")
            continue
        profile = spec.get("profile")
        if profile and profile not in profiles:
            errors.append(
                f"{path}.{key}: requires profile {profile!r}, not declared in metadata.profiles"
            )
            continue
        _check_value(value, spec, profiles, f"{path}.{key}", errors)

    for key, spec in attributes.items():
        if spec.get("requirement") != "required":
            continue
        profile = spec.get("profile")
        if profile and profile not in profiles:
            continue
        if node.get(key) is None:
            errors.append(f"{path}.{key}: required attribute missing")


def _check_value(value, spec, profiles, path, errors):
    if spec.get("is_array"):
        if not isinstance(value, list):
            errors.append(f"{path}: expected an array")
            return
        for index, item in enumerate(value):
            _check_one(item, spec, profiles, f"{path}[{index}]", errors)
    else:
        _check_one(value, spec, profiles, path, errors)


def _check_one(value, spec, profiles, path, errors):
    if spec.get("type") == "object_t":
        obj = schema()["objects"].get(spec.get("object_type"))
        if obj is None:
            errors.append(f"{path}: unknown object type {spec.get('object_type')!r}")
            return
        if not isinstance(value, dict):
            errors.append(f"{path}: expected an object")
            return
        _check_attributes(value, obj.get("attributes", {}), profiles, path, errors)
        at_least_one = (obj.get("constraints") or {}).get("at_least_one")
        if at_least_one and not any(value.get(k) is not None for k in at_least_one):
            errors.append(f"{path}: at_least_one constraint {at_least_one} not satisfied")
        return

    enum = spec.get("enum")
    if enum is not None and str(value) not in enum:
        errors.append(f"{path}: {value!r} is not a valid enum value")
