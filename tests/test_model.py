"""Comprehensive unit tests for dexbuf.model module."""

import hashlib
import io
import os
import struct
import tempfile
import unittest
import zipfile
import zlib
from collections.abc import Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import Any

from dexbuf import (
    AccessFlags,
    Annotation,
    AnnotationVisibility,
    Class,
    ClassLoader,
    ClassLoaderElement,
    CodeItem,
    DexAdapter,
    DexFile,
    EncodedValue,
    Opcode,
    ResolvedClass,
    UnresolvedClass,
    ValueType,
    VdexAdapter,
    VdexFile,
    ZipAdapter,
    ZipArchive,
    is_resolved,
    load,
    open,
)
from dexbuf.leb128 import encode_uleb128
from dexbuf.mutf8 import encode_mutf8


def _encode_uleb128(val: int) -> bytearray:
    return bytearray(encode_uleb128(val))


def _shorty_char(desc: str) -> str:
    if desc.startswith("L") or desc.startswith("["):
        return "L"
    return desc[0]


def _compute_shorty(return_desc: str, param_descs: list[str]) -> str:
    return _shorty_char(return_desc) + "".join(_shorty_char(p) for p in param_descs)


def build_dex_bytes(classes: list[dict[str, Any]]) -> bytes:
    """Build a minimal valid DEX binary buffer for testing."""
    raw_strings = {"V"}
    field_defs: list[dict[str, Any]] = []
    method_defs: list[dict[str, Any]] = []
    proto_defs_set: set[tuple[str, tuple[str, ...]]] = set()

    for c in classes:
        raw_strings.add(c["name"])
        if c.get("super"):
            raw_strings.add(c["super"])
        for iface in c.get("interfaces", []):
            raw_strings.add(iface)
        if c.get("source_file"):
            raw_strings.add(c["source_file"])

        def _collect_ann(ann_list: list[dict[str, Any]]) -> None:
            for ann in ann_list:
                raw_strings.add(ann["type"])
                for ename, evalue in ann.get("elements", {}).items():
                    raw_strings.add(ename)
                    if isinstance(evalue, EncodedValue) and evalue.value_type in (
                        ValueType.STRING,
                        ValueType.TYPE,
                    ):
                        raw_strings.add(evalue.value)

        _collect_ann(c.get("annotations", []))

        for f in c.get("static_fields", []):
            raw_strings.add(f["name"])
            raw_strings.add(f["type"])
            _collect_ann(f.get("annotations", []))
            field_defs.append({"class": c["name"], "name": f["name"], "type": f["type"]})
            if isinstance(f.get("value"), EncodedValue):
                ev: EncodedValue = f["value"]
                if ev.value_type in (ValueType.STRING, ValueType.TYPE):
                    raw_strings.add(ev.value)

        for f in c.get("instance_fields", []):
            raw_strings.add(f["name"])
            raw_strings.add(f["type"])
            _collect_ann(f.get("annotations", []))
            field_defs.append({"class": c["name"], "name": f["name"], "type": f["type"]})

        all_methods = c.get("direct_methods", []) + c.get("virtual_methods", [])
        for m in all_methods:
            raw_strings.add(m["name"])
            ret_type = m.get("return_type", "V")
            raw_strings.add(ret_type)
            params = tuple(m.get("params", []))
            for p in params:
                raw_strings.add(p)
            proto_defs_set.add((ret_type, params))
            shorty = m.get("shorty") or _compute_shorty(ret_type, list(params))
            raw_strings.add(shorty)
            _collect_ann(m.get("annotations", []))
            for p_anns in m.get("parameter_annotations", []):
                _collect_ann(p_anns)
            method_defs.append(
                {
                    "class": c["name"],
                    "name": m["name"],
                    "return_type": ret_type,
                    "params": params,
                    "proto_key": (ret_type, params),
                }
            )

    strings = sorted(raw_strings)
    str_map = {s: i for i, s in enumerate(strings)}

    primitives = {"V", "Z", "B", "S", "C", "I", "J", "F", "D"}
    type_descs = sorted(
        {s for s in strings if s in primitives or s.startswith("L") or s.startswith("[")}
    )
    type_map = {t: i for i, t in enumerate(type_descs)}

    field_ids_sorted = sorted(
        field_defs,
        key=lambda f: (type_map[f["class"]], str_map[f["name"]], type_map[f["type"]]),
    )
    field_id_map = {(f["class"], f["name"], f["type"]): i for i, f in enumerate(field_ids_sorted)}

    proto_ids_sorted = sorted(
        proto_defs_set,
        key=lambda p: (type_map[p[0]], tuple(type_map[pt] for pt in p[1])),
    )
    proto_map = {p: i for i, p in enumerate(proto_ids_sorted)}

    unique_method_defs: dict[tuple[str, str, tuple[str, tuple[str, ...]]], dict[str, Any]] = {}
    for m in method_defs:
        unique_method_defs[(m["class"], m["name"], m["proto_key"])] = m

    method_ids_sorted = sorted(
        unique_method_defs.values(),
        key=lambda m: (type_map[m["class"]], str_map[m["name"]], proto_map[m["proto_key"]]),
    )
    method_id_map = {
        (m["class"], m["name"], m["proto_key"]): i for i, m in enumerate(method_ids_sorted)
    }

    header_size = 0x70
    str_ids_off = header_size
    type_ids_off = str_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(type_descs) * 4
    field_ids_off = proto_ids_off + len(proto_ids_sorted) * 12
    method_ids_off = field_ids_off + len(field_ids_sorted) * 8
    class_defs_off = method_ids_off + len(method_ids_sorted) * 8
    data_off = class_defs_off + len(classes) * 32

    abs_data_start = data_off

    data = bytearray()

    str_offsets = []
    for s in strings:
        str_offsets.append(len(data))
        encoded = encode_mutf8(s, null_terminated=True)
        utf16_len = len(s)
        uleb = _encode_uleb128(utf16_len)
        data.extend(uleb)
        data.extend(encoded)

    iface_offsets = {}
    for c in classes:
        ifaces = c.get("interfaces", [])
        if ifaces:
            while len(data) % 4 != 0:
                data.append(0)
            iface_offsets[c["name"]] = len(data)
            data.extend(struct.pack("<I", len(ifaces)))
            for iface in ifaces:
                data.extend(struct.pack("<H", type_map[iface]))
            if len(ifaces) % 2 == 1:
                data.extend(struct.pack("<H", 0))

    proto_param_offsets = {}
    for ret_type, params in proto_ids_sorted:
        if params:
            while len(data) % 4 != 0:
                data.append(0)
            proto_param_offsets[(ret_type, params)] = len(data)
            data.extend(struct.pack("<I", len(params)))
            for pt in params:
                data.extend(struct.pack("<H", type_map[pt]))
            if len(params) % 2 == 1:
                data.extend(struct.pack("<H", 0))

    class_data_offsets = {}
    static_values_offsets = {}
    class_annotations_directory_offsets = {}

    def _encode_annotation_item(ann_spec: dict[str, Any]) -> bytes:
        type_idx = type_map[ann_spec["type"]]
        visibility = ann_spec.get("visibility", 1)
        elems_dict = ann_spec.get("elements", {})
        elem_bytes = bytearray()
        for ename, evalue in sorted(elems_dict.items(), key=lambda x: str_map[x[0]]):
            elem_bytes.extend(_encode_uleb128(str_map[ename]))
            if isinstance(evalue, EncodedValue) and evalue.value_type in (
                ValueType.STRING,
                ValueType.TYPE,
            ):
                idx_val = (
                    str_map[evalue.value]
                    if evalue.value_type == ValueType.STRING
                    else type_map[evalue.value]
                )
                ev_idx = EncodedValue(
                    value_arg=evalue.value_arg, value_type=evalue.value_type, value=idx_val
                )
                elem_bytes.extend(ev_idx.to_bytes())
            elif isinstance(evalue, EncodedValue):
                elem_bytes.extend(evalue.to_bytes())

        encoded_ann = _encode_uleb128(type_idx) + _encode_uleb128(len(elems_dict)) + elem_bytes
        return bytes([visibility]) + encoded_ann

    for c in classes:
        c_anns = c.get("annotations", [])
        s_fields = c.get("static_fields", [])
        i_fields = c.get("instance_fields", [])
        d_methods = c.get("direct_methods", [])
        v_methods = c.get("virtual_methods", [])

        has_annotations = bool(
            c_anns
            or any(f.get("annotations") for f in s_fields + i_fields)
            or any(
                m.get("annotations") or m.get("parameter_annotations")
                for m in d_methods + v_methods
            )
        )

        if has_annotations:

            def _build_annotation_set(ann_list: list[dict[str, Any]]) -> int:
                if not ann_list:
                    return 0
                item_offs = []
                for ann_spec in ann_list:
                    item_offs.append(len(data))
                    data.extend(_encode_annotation_item(ann_spec))

                while len(data) % 4 != 0:
                    data.append(0)
                set_off = len(data)
                data.extend(struct.pack("<I", len(item_offs)))
                for off in item_offs:
                    data.extend(struct.pack("<I", abs_data_start + off))
                return abs_data_start + set_off

            class_set_off = _build_annotation_set(c_anns)

            field_ann_entries = []
            for f in s_fields + i_fields:
                f_anns = f.get("annotations", [])
                if f_anns:
                    f_idx = field_id_map[(c["name"], f["name"], f["type"])]
                    f_set_off = _build_annotation_set(f_anns)
                    field_ann_entries.append((f_idx, f_set_off))

            method_ann_entries = []
            param_ann_entries = []
            for m in d_methods + v_methods:
                proto_key = (m.get("return_type", "V"), tuple(m.get("params", [])))
                m_idx = method_id_map[(c["name"], m["name"], proto_key)]

                m_anns = m.get("annotations", [])
                if m_anns:
                    m_set_off = _build_annotation_set(m_anns)
                    method_ann_entries.append((m_idx, m_set_off))

                p_anns_list = m.get("parameter_annotations")
                if p_anns_list:
                    param_set_offs = []
                    for p_anns in p_anns_list:
                        p_set_off = _build_annotation_set(p_anns) if p_anns else 0
                        param_set_offs.append(p_set_off)

                    while len(data) % 4 != 0:
                        data.append(0)
                    ref_list_off = len(data)
                    data.extend(struct.pack("<I", len(param_set_offs)))
                    for p_off in param_set_offs:
                        data.extend(struct.pack("<I", p_off))
                    param_ann_entries.append((m_idx, abs_data_start + ref_list_off))

            while len(data) % 4 != 0:
                data.append(0)
            dir_off = len(data)
            data.extend(
                struct.pack(
                    "<4I",
                    class_set_off,
                    len(field_ann_entries),
                    len(method_ann_entries),
                    len(param_ann_entries),
                )
            )
            for f_idx, f_off in field_ann_entries:
                data.extend(struct.pack("<II", f_idx, f_off))
            for m_idx, m_off in method_ann_entries:
                data.extend(struct.pack("<II", m_idx, m_off))
            for m_idx, p_off in param_ann_entries:
                data.extend(struct.pack("<II", m_idx, p_off))

            class_annotations_directory_offsets[c["name"]] = abs_data_start + dir_off

        s_fields = sorted(
            c.get("static_fields", []),
            key=lambda f: field_id_map[(c["name"], f["name"], f["type"])],
        )
        i_fields = sorted(
            c.get("instance_fields", []),
            key=lambda f: field_id_map[(c["name"], f["name"], f["type"])],
        )
        d_methods = sorted(
            c.get("direct_methods", []),
            key=lambda m: method_id_map[
                (c["name"], m["name"], (m.get("return_type", "V"), tuple(m.get("params", []))))
            ],
        )
        v_methods = sorted(
            c.get("virtual_methods", []),
            key=lambda m: method_id_map[
                (c["name"], m["name"], (m.get("return_type", "V"), tuple(m.get("params", []))))
            ],
        )

        method_code_offsets: dict[tuple[str, str, tuple[str, tuple[str, ...]]], int] = {}
        for m in d_methods + v_methods:
            proto_key = (m.get("return_type", "V"), tuple(m.get("params", [])))
            code_spec = m.get("code")
            if code_spec is not None:
                while len(data) % 4 != 0:
                    data.append(0)
                method_code_offsets[(c["name"], m["name"], proto_key)] = len(data)
                if isinstance(code_spec, bytes):
                    if len(code_spec) >= 16 and m.get("is_full_code_item"):
                        data.extend(code_spec)
                    else:
                        reg_sz = m.get("registers_size", 2)
                        ins_sz = m.get(
                            "ins_size",
                            len(proto_key[1])
                            + (0 if (m.get("access_flags", 1) & AccessFlags.STATIC) else 1),
                        )
                        outs_sz = m.get("outs_size", 0)
                        insns_sz = len(code_spec) // 2
                        data.extend(struct.pack("<4H2I", reg_sz, ins_sz, outs_sz, 0, 0, insns_sz))
                        data.extend(code_spec)
                elif hasattr(code_spec, "to_bytes"):
                    data.extend(code_spec.to_bytes())

        if s_fields or i_fields or d_methods or v_methods:
            class_data_offsets[c["name"]] = len(data)
            data.extend(_encode_uleb128(len(s_fields)))
            data.extend(_encode_uleb128(len(i_fields)))
            data.extend(_encode_uleb128(len(d_methods)))
            data.extend(_encode_uleb128(len(v_methods)))

            prev_idx = 0
            for f in s_fields:
                abs_idx = field_id_map[(c["name"], f["name"], f["type"])]
                diff = abs_idx - prev_idx
                prev_idx = abs_idx
                data.extend(_encode_uleb128(diff))
                data.extend(_encode_uleb128(f.get("access_flags", 1)))

            prev_idx = 0
            for f in i_fields:
                abs_idx = field_id_map[(c["name"], f["name"], f["type"])]
                diff = abs_idx - prev_idx
                prev_idx = abs_idx
                data.extend(_encode_uleb128(diff))
                data.extend(_encode_uleb128(f.get("access_flags", 1)))

            prev_idx = 0
            for m in d_methods:
                proto_key = (m.get("return_type", "V"), tuple(m.get("params", [])))
                abs_idx = method_id_map[(c["name"], m["name"], proto_key)]
                diff = abs_idx - prev_idx
                prev_idx = abs_idx
                data.extend(_encode_uleb128(diff))
                data.extend(_encode_uleb128(m.get("access_flags", 1)))
                rel_code_off = method_code_offsets.get((c["name"], m["name"], proto_key))
                abs_code_off = (abs_data_start + rel_code_off) if rel_code_off is not None else 0
                data.extend(_encode_uleb128(abs_code_off))

            prev_idx = 0
            for m in v_methods:
                proto_key = (m.get("return_type", "V"), tuple(m.get("params", [])))
                abs_idx = method_id_map[(c["name"], m["name"], proto_key)]
                diff = abs_idx - prev_idx
                prev_idx = abs_idx
                data.extend(_encode_uleb128(diff))
                data.extend(_encode_uleb128(m.get("access_flags", 1)))
                rel_code_off = method_code_offsets.get((c["name"], m["name"], proto_key))
                abs_code_off = (abs_data_start + rel_code_off) if rel_code_off is not None else 0
                data.extend(_encode_uleb128(abs_code_off))

        static_vals = [
            f["value"] for f in s_fields if "value" in f and isinstance(f["value"], EncodedValue)
        ]
        if static_vals:
            static_values_offsets[c["name"]] = len(data)
            data.extend(_encode_uleb128(len(static_vals)))
            for ev in static_vals:
                if ev.value_type in (ValueType.STRING, ValueType.TYPE):
                    idx_val = (
                        str_map[ev.value]
                        if ev.value_type == ValueType.STRING
                        else type_map[ev.value]
                    )
                    ev_with_idx = EncodedValue(
                        value_arg=ev.value_arg,
                        value_type=ev.value_type,
                        value=idx_val,
                    )
                    data.extend(ev_with_idx.to_bytes())
                else:
                    data.extend(ev.to_bytes())

    buf = bytearray()
    buf.extend(b"\x00" * header_size)

    for off in str_offsets:
        buf.extend(struct.pack("<I", abs_data_start + off))

    for tdesc in type_descs:
        buf.extend(struct.pack("<I", str_map[tdesc]))

    for ret_type, params in proto_ids_sorted:
        shorty = _compute_shorty(ret_type, list(params))
        shorty_idx = str_map[shorty]
        ret_type_idx = type_map[ret_type]
        params_off = (
            (abs_data_start + proto_param_offsets[(ret_type, params)])
            if (ret_type, params) in proto_param_offsets
            else 0
        )
        buf.extend(struct.pack("<III", shorty_idx, ret_type_idx, params_off))

    for f in field_ids_sorted:
        buf.extend(
            struct.pack(
                "<HHI",
                type_map[f["class"]],
                type_map[f["type"]],
                str_map[f["name"]],
            )
        )

    for m in method_ids_sorted:
        buf.extend(
            struct.pack(
                "<HHI",
                type_map[m["class"]],
                proto_map[m["proto_key"]],
                str_map[m["name"]],
            )
        )

    for c in classes:
        c_idx = type_map[c["name"]]
        flags = c.get("access_flags", 1)
        s_idx = type_map[c["super"]] if c.get("super") else 0xFFFF_FFFF
        i_off = abs_data_start + iface_offsets[c["name"]] if c["name"] in iface_offsets else 0
        sf_idx = str_map[c["source_file"]] if c.get("source_file") else 0xFFFF_FFFF
        cd_off = (
            abs_data_start + class_data_offsets[c["name"]] if c["name"] in class_data_offsets else 0
        )
        sv_off = (
            abs_data_start + static_values_offsets[c["name"]]
            if c["name"] in static_values_offsets
            else 0
        )
        ann_off = class_annotations_directory_offsets.get(c["name"], 0)
        buf.extend(struct.pack("<8I", c_idx, flags, s_idx, i_off, sf_idx, ann_off, cd_off, sv_off))

    buf.extend(data)

    while len(buf) % 4 != 0:
        buf.append(0)
    map_off = len(buf)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), str_ids_off),
        (0x0002, len(type_descs), type_ids_off),
    ]
    if proto_ids_sorted:
        map_items.append((0x0003, len(proto_ids_sorted), proto_ids_off))
    if field_ids_sorted:
        map_items.append((0x0004, len(field_ids_sorted), field_ids_off))
    if method_ids_sorted:
        map_items.append((0x0005, len(method_ids_sorted), method_ids_off))
    map_items.append((0x0006, len(classes), class_defs_off))
    map_items.append((0x1000, 1, map_off))

    map_bytes = struct.pack("<I", len(map_items))
    for k, sz, off in map_items:
        map_bytes += struct.pack("<HHII", k, 0, sz, off)
    buf.extend(map_bytes)

    file_size = len(buf)
    data_size = file_size - abs_data_start

    magic = b"dex\n035\x00"
    struct.pack_into(
        "<8sI20sIII", buf, 0, magic, 0, b"\x00" * 20, file_size, header_size, 0x12345678
    )
    struct.pack_into("<I", buf, 0x34, map_off)
    struct.pack_into(
        "<IIIIII",
        buf,
        0x38,
        len(strings),
        str_ids_off,
        len(type_descs),
        type_ids_off,
        len(proto_ids_sorted),
        proto_ids_off if proto_ids_sorted else 0,
    )
    struct.pack_into(
        "<IIIIII",
        buf,
        0x50,
        len(field_ids_sorted),
        field_ids_off if field_ids_sorted else 0,
        len(method_ids_sorted),
        method_ids_off if method_ids_sorted else 0,
        len(classes),
        class_defs_off,
    )
    struct.pack_into("<II", buf, 0x68, data_size, abs_data_start)

    sig = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sig
    chk = zlib.adler32(buf[12:]) & 0xFFFF_FFFF
    struct.pack_into("<I", buf, 8, chk)

    return bytes(buf)


def build_vdex_bytes(dex_buffers: list[bytes]) -> bytes:
    """Build a minimal valid VDEX v027 binary buffer for testing."""
    buf = bytearray()
    buf.extend(struct.pack("<4s4sI", b"vdex", b"027\x00", 2))

    chk_size = len(dex_buffers) * 4
    dex_sec_offset = 12 + 2 * 12 + chk_size
    while dex_sec_offset % 4 != 0:
        dex_sec_offset += 1

    dex_payload = bytearray()
    for d in dex_buffers:
        dex_payload.extend(d)
        while len(dex_payload) % 4 != 0:
            dex_payload.append(0)

    buf.extend(struct.pack("<3I", 0, 12 + 2 * 12, chk_size))
    buf.extend(struct.pack("<3I", 1, dex_sec_offset, len(dex_payload)))

    for d in dex_buffers:
        chk = struct.unpack_from("<I", d, 8)[0]
        buf.extend(struct.pack("<I", chk))

    while len(buf) < dex_sec_offset:
        buf.append(0)

    buf.extend(dex_payload)
    return bytes(buf)


class TestClassHierarchy(unittest.TestCase):
    def test_is_resolved_type_guard(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        resolved_cls = loader["com.example.Foo"]
        unresolved_cls = UnresolvedClass("Landroid/app/Activity;")

        self.assertTrue(is_resolved(resolved_cls))
        self.assertFalse(is_resolved(unresolved_cls))

        # Test type narrowing behavior in conditional branch
        def check_narrowing(c: Class) -> str:
            if is_resolved(c):
                # c is narrowed to ResolvedClass
                return f"Resolved: {c.dex_file!r}"
            else:
                # c is narrowed to UnresolvedClass
                return f"Unresolved: {c.name}"

        self.assertTrue(check_narrowing(resolved_cls).startswith("Resolved:"))
        self.assertEqual(check_narrowing(unresolved_cls), "Unresolved: android.app.Activity")

    def test_unresolved_class_properties_and_normalization(self) -> None:
        unresolved1 = UnresolvedClass.from_name_or_descriptor("android.app.Activity")
        self.assertFalse(unresolved1.is_resolved)
        self.assertEqual(unresolved1.descriptor, "Landroid/app/Activity;")
        self.assertEqual(unresolved1.name, "android.app.Activity")
        self.assertEqual(unresolved1.package, "android.app")
        self.assertEqual(unresolved1.simple_name, "Activity")
        self.assertEqual(str(unresolved1), "android.app.Activity")
        self.assertEqual(repr(unresolved1), "<UnresolvedClass 'android.app.Activity'>")

        unresolved2 = UnresolvedClass("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved2)
        self.assertEqual(hash(unresolved1), hash(unresolved2))

        unresolved3 = UnresolvedClass.from_name_or_descriptor("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved3)

        unresolved_arr = UnresolvedClass("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.descriptor, "[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.name, "android.app.Activity[]")

        unresolved_arr2 = UnresolvedClass.from_name_or_descriptor("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr, unresolved_arr2)

        default_pkg = UnresolvedClass.from_name_or_descriptor("GlobalClass")
        self.assertEqual(default_pkg.descriptor, "LGlobalClass;")
        self.assertEqual(default_pkg.package, "")
        self.assertEqual(default_pkg.simple_name, "GlobalClass")

    def test_resolved_class_properties_and_flags(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(
                        AccessFlags.PUBLIC
                        | AccessFlags.FINAL
                        | AccessFlags.SYNTHETIC
                        | AccessFlags.ENUM
                    ),
                    "source_file": "Foo.java",
                }
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        cls = loader.load_class("com.example.Foo")
        self.assertIsNotNone(cls)
        assert cls is not None
        self.assertTrue(cls.is_resolved)
        self.assertEqual(cls.descriptor, "Lcom/example/Foo;")
        self.assertEqual(cls.name, "com.example.Foo")
        self.assertEqual(cls.package, "com.example")
        self.assertEqual(cls.simple_name, "Foo")
        self.assertEqual(cls.loader, loader)
        self.assertEqual(cls.dex_file, dex)
        self.assertEqual(cls.source_file, "Foo.java")
        self.assertTrue(cls.is_public)
        self.assertTrue(cls.is_final)
        self.assertFalse(cls.is_interface)
        self.assertFalse(cls.is_abstract)
        self.assertTrue(cls.is_synthetic)
        self.assertFalse(cls.is_annotation)
        self.assertTrue(cls.is_enum)
        self.assertEqual(str(cls), "com.example.Foo")
        self.assertEqual(repr(cls), "<Class 'com.example.Foo'>")

    def test_resolved_class_superclass_and_interfaces(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Child;",
                    "super": "Lcom/example/Parent;",
                    "interfaces": ["Lcom/example/Iface;", "Landroid/view/View;"],
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Parent;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Iface;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC | AccessFlags.INTERFACE),
                },
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        child = loader["com.example.Child"]
        parent = child.super_class
        self.assertIsInstance(parent, ResolvedClass)
        assert parent is not None
        self.assertEqual(parent.name, "com.example.Parent")

        # Parent's superclass is java.lang.Object which is external to loader
        obj_super = parent.super_class
        self.assertIsInstance(obj_super, UnresolvedClass)
        assert obj_super is not None
        self.assertEqual(obj_super.name, "java.lang.Object")

        ifaces = child.interfaces
        self.assertEqual(len(ifaces), 2)
        self.assertIsInstance(ifaces[0], ResolvedClass)
        self.assertEqual(ifaces[0].name, "com.example.Iface")
        self.assertIsInstance(ifaces[1], UnresolvedClass)
        self.assertEqual(ifaces[1].name, "android.view.View")

    def test_java_lang_object_superclass_none(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Ljava/lang/Object;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC),
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        obj_cls = loader["java.lang.Object"]
        self.assertIsNone(obj_cls.super_class)

    def test_equality_and_hashing(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex1 = DexFile(dex_bytes)
        loader1 = ClassLoader.from_elements([dex1])
        cls1 = loader1["com.example.Foo"]
        cls2 = loader1["com.example.Foo"]

        dex2 = DexFile(dex_bytes)
        loader2 = ClassLoader.from_elements([dex2])
        cls_other_loader = loader2["com.example.Foo"]

        unresolved1 = UnresolvedClass.from_name_or_descriptor("com.example.Foo")
        unresolved2 = UnresolvedClass("Lcom/example/Foo;")

        # UnresolvedClass equality and hash
        self.assertEqual(unresolved1, unresolved2)
        self.assertEqual(hash(unresolved1), hash(unresolved2))
        self.assertNotEqual(unresolved1, "com.example.Foo")

        # ResolvedClass equality and hash within same ClassLoader
        self.assertEqual(cls1, cls2)
        self.assertEqual(hash(cls1), hash(cls2))

        # ResolvedClass equality and hash across different ClassLoaders
        self.assertNotEqual(cls1, cls_other_loader)

        # Cross type comparisons
        self.assertNotEqual(cls1, unresolved1)
        self.assertNotEqual(unresolved1, cls1)
        self.assertNotEqual(cls1, "com.example.Foo")


class TestClassLoader(unittest.TestCase):
    def test_element_type_validation(self) -> None:
        with self.assertRaises(TypeError):
            ClassLoader(["invalid_path_str"])  # type: ignore[arg-type]

        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        vdex_bytes = build_vdex_bytes([build_dex_bytes([])])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", build_dex_bytes([]))
        zip_archive = ZipArchive(buf.getvalue())

        # ClassLoader.__init__ strictly rejects raw unadapted containers
        with self.assertRaises(TypeError):
            ClassLoader([dex])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ClassLoader([vdex])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ClassLoader([zip_archive])  # type: ignore[arg-type]

        # ClassLoader.from_elements wraps raw containers into adapters
        loader = ClassLoader.from_elements([dex])
        self.assertFalse(hasattr(loader, "dex_files"))
        self.assertEqual(len(loader.elements), 1)
        self.assertIsInstance(loader.elements[0], DexAdapter)

        # Direct ClassLoader instantiation with ClassLoaderElement
        adapter = DexAdapter(dex, loader)
        strict_loader = ClassLoader([adapter])
        self.assertEqual(strict_loader.elements, (adapter,))

        # Nested ClassLoader as element
        nested_loader = ClassLoader([strict_loader])
        self.assertEqual(nested_loader.elements, (strict_loader,))

        # from_elements rejects invalid types
        with self.assertRaises(TypeError):
            ClassLoader.from_elements(["invalid_path_str"])  # type: ignore[arg-type]

    def test_resolution_order_parent_first_self_first_interleaved(self) -> None:
        parent_dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "ParentFoo.java",
                    }
                ]
            )
        )
        child_dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "ChildFoo.java",
                    }
                ]
            )
        )

        parent_loader = ClassLoader.from_elements([parent_dex])

        # Parent-first loader
        parent_first = ClassLoader.from_elements([parent_loader, child_dex])
        foo_pf = parent_first["com.example.Foo"]
        self.assertEqual(foo_pf.source_file, "ParentFoo.java")

        # Self-first loader
        self_first = ClassLoader.from_elements([child_dex, parent_loader])
        foo_sf = self_first["com.example.Foo"]
        self.assertEqual(foo_sf.source_file, "ChildFoo.java")

        # Interleaved loader
        interleaved = ClassLoader.from_elements([parent_dex, parent_loader, child_dex])
        foo_il = interleaved["com.example.Foo"]
        self.assertEqual(foo_il.source_file, "ParentFoo.java")

    def test_resolution_caching(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        loader = ClassLoader.from_elements([dex])

        cls1 = loader.load_class("com.example.Foo")
        cls2 = loader.load_class("Lcom/example/Foo;")
        self.assertIs(cls1, cls2)

        missing1 = loader.load_class("com.example.Missing")
        self.assertIsNone(missing1)

        missing2 = loader.load_class("com.example.Missing")
        self.assertIsNone(missing2)

    def test_find_all_shadow_classes(self) -> None:
        dex1 = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "Foo1.java",
                    }
                ]
            )
        )
        dex2 = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "Foo2.java",
                    }
                ]
            )
        )

        loader = ClassLoader.from_elements([dex1, dex2])
        all_foos = loader.find_all("com.example.Foo")
        self.assertEqual(len(all_foos), 2)
        self.assertEqual(all_foos[0].source_file, "Foo1.java")
        self.assertEqual(all_foos[1].source_file, "Foo2.java")

        iter_classes = list(loader)
        self.assertEqual(len(iter_classes), 2)
        self.assertEqual(len(loader), 2)
        self.assertEqual(iter_classes[0].source_file, "Foo1.java")
        self.assertEqual(iter_classes[1].source_file, "Foo2.java")

    def test_find_glob_pattern(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/MainActivity;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                    {
                        "name": "Lcom/example/DetailActivity;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                    {
                        "name": "Lcom/example/util/Helper;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                ]
            )
        )
        loader = ClassLoader.from_elements([dex])

        activities = loader.find("*.Activity")
        # Simple name ends with Activity, but full name is com.example.*Activity
        self.assertEqual(len(activities), 0)

        activities_wildcard = loader.find("*Activity")
        self.assertEqual(len(activities_wildcard), 2)
        names = {a.name for a in activities_wildcard}
        self.assertEqual(names, {"com.example.MainActivity", "com.example.DetailActivity"})

    def test_mapping_semantics(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [
                    {"name": "Lcom/example/A;", "super": "Ljava/lang/Object;", "access_flags": 1},
                    {"name": "Lcom/example/B;", "super": "Ljava/lang/Object;", "access_flags": 1},
                ]
            )
        )
        loader = ClassLoader.from_elements([dex])

        # __getitem__
        cls_a = loader["com.example.A"]
        self.assertEqual(cls_a.name, "com.example.A")
        with self.assertRaises(KeyError):
            _ = loader["com.example.C"]

        # get
        self.assertEqual(loader.get("com.example.A"), cls_a)
        self.assertIsNone(loader.get("com.example.C"))

        # __contains__
        self.assertIn("com.example.A", loader)
        self.assertIn("Lcom/example/A;", loader)
        self.assertIn(cls_a, loader)
        self.assertNotIn("com.example.C", loader)
        self.assertNotIn(123, loader)

        # __iter__ and __len__
        all_classes = list(loader)
        self.assertEqual(len(all_classes), 2)
        self.assertEqual(len(loader), 2)

    def test_context_manager_and_close(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        res_mock = io.BytesIO(b"data")

        with ClassLoader.from_elements([dex]) as loader:
            loader._resources.append(res_mock)
            self.assertFalse(res_mock.closed)

        self.assertTrue(res_mock.closed)


class TestMultiDexAndContainers(unittest.TestCase):
    def test_multidex_apk_class_resolution(self) -> None:
        dex1 = build_dex_bytes(
            [{"name": "Lcom/example/Base;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex2 = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Derived;",
                    "super": "Lcom/example/Base;",
                    "access_flags": 1,
                }
            ]
        )

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex1)
            zf.writestr("classes2.dex", dex2)

        zip_archive = ZipArchive(buf.getvalue())
        loader = ClassLoader.from_elements([zip_archive])

        derived = loader["com.example.Derived"]
        base = derived.super_class

        self.assertIsInstance(base, ResolvedClass)
        assert base is not None
        self.assertEqual(base.name, "com.example.Base")

    def test_vdex_container_class_resolution(self) -> None:
        dex1 = build_dex_bytes(
            [{"name": "Lcom/example/VdexClass;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        vdex_bytes = build_vdex_bytes([dex1])
        vdex = VdexFile(vdex_bytes)

        loader = ClassLoader.from_elements([vdex])
        cls = loader["com.example.VdexClass"]
        self.assertEqual(cls.name, "com.example.VdexClass")


class TestTopLevelEntryPoints(unittest.TestCase):
    def test_load_entry_point_format_detection(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader_dex = load(dex_bytes)
        self.assertIn("com.example.Foo", loader_dex)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        loader_zip = load(buf.getvalue())
        self.assertIn("com.example.Foo", loader_zip)

        vdex_bytes = build_vdex_bytes([dex_bytes])
        loader_vdex = load(vdex_bytes)
        self.assertIn("com.example.Foo", loader_vdex)

        with self.assertRaises(ValueError):
            load(b"INVALID_HEADER")

    def test_open_entry_point_mmap_and_read(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )

        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
            f.write(dex_bytes)
            f.flush()
            temp_path = f.name

        try:
            # mmap=True
            with open(temp_path, mmap=True) as loader_mmap:
                self.assertIn("com.example.Foo", loader_mmap)

            # mmap=False
            with open(temp_path, mmap=False) as loader_read:
                self.assertIn("com.example.Foo", loader_read)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestAdaptersAndCustomElements(unittest.TestCase):
    def test_adapters_protocol_conformance(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        vdex_bytes = build_vdex_bytes([dex_bytes])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        zip_archive = ZipArchive(buf.getvalue())

        dex_adapter = DexAdapter(dex, loader)
        vdex_adapter = VdexAdapter(vdex, loader)
        zip_adapter = ZipAdapter(zip_archive, loader)

        self.assertIsInstance(dex_adapter, ClassLoaderElement)
        self.assertIsInstance(vdex_adapter, ClassLoaderElement)
        self.assertIsInstance(zip_adapter, ClassLoaderElement)
        self.assertIsInstance(loader, ClassLoaderElement)

    def test_direct_adapter_queries(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        vdex_bytes = build_vdex_bytes([dex_bytes])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        zip_archive = ZipArchive(buf.getvalue())

        # DexAdapter
        dex_adapter = DexAdapter(dex, loader)
        self.assertIs(dex_adapter.dex_file, dex)
        cls_dex = dex_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_dex)
        self.assertEqual(len(dex_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(dex_adapter)), 1)
        self.assertEqual(len(dex_adapter), 1)

        # VdexAdapter
        vdex_adapter = VdexAdapter(vdex, loader)
        self.assertIs(vdex_adapter.vdex_file, vdex)
        cls_vdex = vdex_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_vdex)
        self.assertEqual(len(vdex_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(vdex_adapter)), 1)
        self.assertEqual(len(vdex_adapter), 1)

        # ZipAdapter
        zip_adapter = ZipAdapter(zip_archive, loader)
        self.assertIs(zip_adapter.archive, zip_archive)
        cls_zip = zip_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_zip)
        self.assertEqual(len(zip_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(zip_adapter)), 1)
        self.assertEqual(len(zip_adapter), 1)

    def test_custom_user_element(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Custom;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)

        class CustomElement:
            __slots__ = ("_dex",)

            def __init__(self, dex_file: DexFile) -> None:
                self._dex = dex_file

            def load_class(self, descriptor: str) -> ResolvedClass | None:
                cdef = self._dex.find_class_def(descriptor)
                if cdef is not None:
                    # Construct dummy ResolvedClass with dummy loader
                    return ResolvedClass(ClassLoader(), self._dex, cdef)
                return None

            def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
                cls = self.load_class(descriptor)
                return [cls] if cls is not None else []

            def __iter__(self) -> Iterator[ResolvedClass]:
                for cdef in self._dex.class_defs:
                    yield ResolvedClass(ClassLoader(), self._dex, cdef)

            def __len__(self) -> int:
                return len(self._dex.class_defs)

        custom_elem = CustomElement(dex)
        self.assertIsInstance(custom_elem, ClassLoaderElement)

        loader = ClassLoader([custom_elem])
        cls = loader.load_class("com.example.Custom")
        self.assertIsNotNone(cls)
        assert cls is not None
        self.assertEqual(cls.name, "com.example.Custom")
        self.assertEqual(len(loader.find_all("com.example.Custom")), 1)
        self.assertIn("com.example.Custom", loader)


class TestFieldDomainModel(unittest.TestCase):
    def test_class_without_fields(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/NoFields;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NoFields"]

        self.assertEqual(cls.fields, ())
        self.assertEqual(cls.static_fields, ())
        self.assertEqual(cls.instance_fields, ())
        self.assertIsNone(cls.get_field("any"))

    def test_static_and_instance_fields(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC
                                | AccessFlags.STATIC
                                | AccessFlags.FINAL
                                | AccessFlags.SYNTHETIC
                            ),
                            "value": EncodedValue(
                                value_arg=0, value_type=ValueType.STRING, value="FOO_TAG"
                            ),
                        }
                    ],
                    "instance_fields": [
                        {
                            "name": "count",
                            "type": "I",
                            "access_flags": int(
                                AccessFlags.PRIVATE | AccessFlags.VOLATILE | AccessFlags.TRANSIENT
                            ),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Foo"]

        self.assertEqual(len(cls.fields), 2)
        self.assertEqual(len(cls.static_fields), 1)
        self.assertEqual(len(cls.instance_fields), 1)

        f_tag = cls.get_field("TAG")
        self.assertIsNotNone(f_tag)
        assert f_tag is not None

        self.assertEqual(f_tag.defining_class, cls)
        self.assertEqual(f_tag.name, "TAG")
        self.assertEqual(f_tag.type_descriptor, "Ljava/lang/String;")
        self.assertEqual(f_tag.type_name, "java.lang.String")
        self.assertTrue(f_tag.is_static)
        self.assertTrue(f_tag.is_public)
        self.assertFalse(f_tag.is_private)
        self.assertFalse(f_tag.is_protected)
        self.assertTrue(f_tag.is_final)
        self.assertFalse(f_tag.is_volatile)
        self.assertFalse(f_tag.is_transient)
        self.assertTrue(f_tag.is_synthetic)
        self.assertFalse(f_tag.is_enum)
        self.assertIsInstance(f_tag.initial_value, EncodedValue)
        assert f_tag.initial_value is not None
        self.assertEqual(f_tag.initial_value.value_type, ValueType.STRING)
        self.assertIsInstance(f_tag.initial_value.value, int)
        self.assertEqual(repr(f_tag), "<Field 'com.example.Foo.TAG: java.lang.String'>")
        self.assertEqual(str(f_tag), "com.example.Foo.TAG: java.lang.String")

        f_count = cls.get_field("count")
        self.assertIsNotNone(f_count)
        assert f_count is not None

        self.assertEqual(f_count.name, "count")
        self.assertEqual(f_count.type_descriptor, "I")
        self.assertEqual(f_count.type_name, "int")
        self.assertFalse(f_count.is_static)
        self.assertTrue(f_count.is_private)
        self.assertTrue(f_count.is_volatile)
        self.assertTrue(f_count.is_transient)
        self.assertIsNone(f_count.initial_value)

    def test_field_type_resolution(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Holder;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {"name": "resolvedRef", "type": "Lcom/example/Target;", "access_flags": 1},
                        {
                            "name": "unresolvedRef",
                            "type": "Landroid/app/Activity;",
                            "access_flags": 1,
                        },
                        {"name": "primitiveInt", "type": "I", "access_flags": 1},
                    ],
                },
                {
                    "name": "Lcom/example/Target;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        holder = loader["com.example.Holder"]

        f_res = holder.get_field("resolvedRef")
        assert f_res is not None
        self.assertIsInstance(f_res.type_class, ResolvedClass)
        self.assertEqual(f_res.type_class.name, "com.example.Target")
        self.assertIs(f_res.type, f_res.type_class)

        f_unres = holder.get_field("unresolvedRef")
        assert f_unres is not None
        self.assertIsInstance(f_unres.type_class, UnresolvedClass)
        self.assertEqual(f_unres.type_class.name, "android.app.Activity")

        f_prim = holder.get_field("primitiveInt")
        assert f_prim is not None
        self.assertIsInstance(f_prim.type_class, UnresolvedClass)
        self.assertEqual(f_prim.type_class.name, "int")

    def test_static_initial_values(self) -> None:
        ev_ival = EncodedValue(value_arg=3, value_type=ValueType.INT, value=42)
        ev_sval = EncodedValue(value_arg=0, value_type=ValueType.STRING, value="hello")
        ev_fval = EncodedValue(value_arg=3, value_type=ValueType.FLOAT, value=3.14)
        ev_bval = EncodedValue(value_arg=1, value_type=ValueType.BOOLEAN, value=True)
        ev_tval = EncodedValue(value_arg=0, value_type=ValueType.TYPE, value="Lcom/example/Values;")

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Values;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "static_fields": [
                        {
                            "name": "iVal",
                            "type": "I",
                            "access_flags": 0x8,
                            "value": ev_ival,
                        },
                        {
                            "name": "sVal",
                            "type": "Ljava/lang/String;",
                            "access_flags": 0x8,
                            "value": ev_sval,
                        },
                        {
                            "name": "fVal",
                            "type": "F",
                            "access_flags": 0x8,
                            "value": ev_fval,
                        },
                        {
                            "name": "bVal",
                            "type": "Z",
                            "access_flags": 0x8,
                            "value": ev_bval,
                        },
                        {
                            "name": "tVal",
                            "type": "Ljava/lang/Class;",
                            "access_flags": 0x8,
                            "value": ev_tval,
                        },
                        {
                            "name": "uninitVal",
                            "type": "I",
                            "access_flags": 0x8,
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Values"]

        f_ival = cls.get_field("iVal")
        assert f_ival is not None
        self.assertIsInstance(f_ival.initial_value, EncodedValue)
        self.assertEqual(f_ival.initial_value.value_type, ValueType.INT)
        self.assertEqual(f_ival.initial_value.value, 42)

        f_sval = cls.get_field("sVal")
        assert f_sval is not None
        self.assertIsInstance(f_sval.initial_value, EncodedValue)
        self.assertEqual(f_sval.initial_value.value_type, ValueType.STRING)

        f_fval = cls.get_field("fVal")
        assert f_fval is not None
        self.assertIsInstance(f_fval.initial_value, EncodedValue)
        self.assertEqual(f_fval.initial_value.value_type, ValueType.FLOAT)

        f_bval = cls.get_field("bVal")
        assert f_bval is not None
        self.assertIsInstance(f_bval.initial_value, EncodedValue)
        self.assertEqual(f_bval.initial_value.value_type, ValueType.BOOLEAN)

        f_tval = cls.get_field("tVal")
        assert f_tval is not None
        self.assertIsInstance(f_tval.initial_value, EncodedValue)
        self.assertEqual(f_tval.initial_value.value_type, ValueType.TYPE)

        f_uninit = cls.get_field("uninitVal")
        assert f_uninit is not None
        self.assertIsNone(f_uninit.initial_value)

    def test_field_equality_and_hash(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {"name": "fieldA", "type": "I", "access_flags": 1},
                        {"name": "fieldB", "type": "I", "access_flags": 1},
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        f1_a = cls1.get_field("fieldA")
        f1_a_again = cls1.get_field("fieldA")
        f1_b = cls1.get_field("fieldB")
        f2_a = cls2.get_field("fieldA")

        assert f1_a is not None and f1_a_again is not None and f1_b is not None and f2_a is not None

        self.assertEqual(f1_a, f1_a_again)
        self.assertEqual(hash(f1_a), hash(f1_a_again))

        self.assertNotEqual(f1_a, f1_b)
        self.assertNotEqual(f1_a, f2_a)  # Different loader identity on defining class
        self.assertNotEqual(f1_a, "not_a_field")


class TestMethodDomainModel(unittest.TestCase):
    def test_class_without_methods(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/NoMethods;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NoMethods"]

        self.assertEqual(cls.methods, ())
        self.assertEqual(cls.direct_methods, ())
        self.assertEqual(cls.virtual_methods, ())
        self.assertEqual(cls.constructors, ())
        self.assertIsNone(cls.get_method("any"))
        self.assertEqual(cls.find_methods("any"), [])

    def test_direct_virtual_methods_and_constructors(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "<init>",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "<clinit>",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(
                                AccessFlags.STATIC | AccessFlags.CONSTRUCTOR | AccessFlags.SYNTHETIC
                            ),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "privateHelper",
                            "return_type": "Z",
                            "params": ["Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PRIVATE | AccessFlags.FINAL),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                    ],
                    "virtual_methods": [
                        {
                            "name": "doStuff",
                            "return_type": "I",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.SYNCHRONIZED),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "doStuff",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.VARARGS),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Foo"]

        self.assertEqual(len(cls.direct_methods), 3)
        self.assertEqual(len(cls.virtual_methods), 2)
        self.assertEqual(len(cls.methods), 5)

        # constructors
        ctors = cls.constructors
        self.assertEqual(len(ctors), 2)
        ctor_names = {c.name for c in ctors}
        self.assertEqual(ctor_names, {"<init>", "<clinit>"})

        init_m = cls.get_method("<init>")
        self.assertIsNotNone(init_m)
        assert init_m is not None
        self.assertTrue(init_m.is_direct)
        self.assertFalse(init_m.is_virtual)
        self.assertTrue(init_m.is_constructor)
        self.assertTrue(init_m.is_public)
        self.assertEqual(init_m.defining_class, cls)

    def test_method_signatures_and_type_resolution(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Service;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "process",
                            "return_type": "Lcom/example/Result;",
                            "params": ["Lcom/example/Param;", "Landroid/content/Context;", "I"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        }
                    ],
                },
                {
                    "name": "Lcom/example/Result;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
                {
                    "name": "Lcom/example/Param;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        service_cls = loader["com.example.Service"]

        m = service_cls.get_method("process")
        self.assertIsNotNone(m)
        assert m is not None

        self.assertEqual(m.name, "process")
        self.assertEqual(m.shorty, "LLLI")
        self.assertEqual(m.return_type_descriptor, "Lcom/example/Result;")
        self.assertEqual(m.return_type_name, "com.example.Result")
        self.assertIsInstance(m.return_type_class, ResolvedClass)
        self.assertEqual(m.return_type_class.name, "com.example.Result")
        self.assertIs(m.return_type, m.return_type_class)

        self.assertEqual(
            m.parameter_type_descriptors,
            ("Lcom/example/Param;", "Landroid/content/Context;", "I"),
        )
        self.assertEqual(
            m.parameter_type_names,
            ("com.example.Param", "android.content.Context", "int"),
        )

        ptypes = m.parameter_types
        self.assertEqual(len(ptypes), 3)
        self.assertIsInstance(ptypes[0], ResolvedClass)
        self.assertEqual(ptypes[0].name, "com.example.Param")
        self.assertIsInstance(ptypes[1], UnresolvedClass)
        self.assertEqual(ptypes[1].name, "android.content.Context")
        self.assertIsInstance(ptypes[2], UnresolvedClass)
        self.assertEqual(ptypes[2].name, "int")

        self.assertEqual(
            m.descriptor, "(Lcom/example/Param;Landroid/content/Context;I)Lcom/example/Result;"
        )
        expected_str = (
            "com.example.Result com.example.Service.process"
            "(com.example.Param, android.content.Context, int)"
        )
        self.assertEqual(str(m), expected_str)

        expected_repr = (
            "<Method 'com.example.Service.process"
            "(Lcom/example/Param;Landroid/content/Context;I)Lcom/example/Result;'>"
        )
        self.assertEqual(repr(m), expected_repr)

    def test_has_code_and_code_item_access(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/NativeClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "concreteMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "nativeMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.NATIVE),
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NativeClass"]

        m_concrete = cls.get_method("concreteMethod")
        assert m_concrete is not None
        self.assertTrue(m_concrete.has_code)
        self.assertIsNotNone(m_concrete.code)
        assert m_concrete.code is not None
        from dexbuf.model import Code

        self.assertIsInstance(m_concrete.code, Code)
        self.assertIsInstance(m_concrete.code.raw, CodeItem)

        m_native = cls.get_method("nativeMethod")
        assert m_native is not None
        self.assertFalse(m_native.has_code)
        self.assertIsNone(m_native.code)
        self.assertTrue(m_native.is_native)

    def test_lookups_get_method_and_find_methods(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Overload;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "compute",
                            "return_type": "I",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        },
                        {
                            "name": "compute",
                            "return_type": "Ljava/lang/String;",
                            "params": ["Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Overload"]

        # find_methods
        matches = cls.find_methods("compute")
        self.assertEqual(len(matches), 2)

        # get_method without descriptor returns first match
        m1 = cls.get_method("compute")
        self.assertIsNotNone(m1)
        assert m1 is not None
        self.assertEqual(m1, matches[0])

        # get_method with descriptor
        m_int = cls.get_method("compute", "(I)I")
        self.assertIsNotNone(m_int)
        assert m_int is not None
        self.assertEqual(m_int.descriptor, "(I)I")

        m_str = cls.get_method("compute", "(Ljava/lang/String;)Ljava/lang/String;")
        self.assertIsNotNone(m_str)
        assert m_str is not None
        self.assertEqual(m_str.descriptor, "(Ljava/lang/String;)Ljava/lang/String;")

        # non-existent
        self.assertIsNone(cls.get_method("compute", "(F)V"))
        self.assertIsNone(cls.get_method("nonExistent"))

    def test_method_flags_convenience(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/FlagsTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "allFlagsMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(
                                AccessFlags.PROTECTED
                                | AccessFlags.STATIC
                                | AccessFlags.FINAL
                                | AccessFlags.SYNTHETIC
                                | AccessFlags.BRIDGE
                                | AccessFlags.VARARGS
                                | AccessFlags.ABSTRACT
                                | AccessFlags.STRICTFP
                            ),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.FlagsTest"]

        m = cls.get_method("allFlagsMethod")
        assert m is not None

        self.assertTrue(m.is_protected)
        self.assertTrue(m.is_static)
        self.assertTrue(m.is_final)
        self.assertTrue(m.is_synthetic)
        self.assertTrue(m.is_bridge)
        self.assertTrue(m.is_varargs)
        self.assertTrue(m.is_abstract)
        self.assertTrue(m.is_strictfp)
        self.assertFalse(m.is_public)
        self.assertFalse(m.is_private)
        self.assertFalse(m.is_synchronized)
        self.assertFalse(m.is_native)

    def test_method_equality_and_hash(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {"name": "m1", "return_type": "V", "params": [], "access_flags": 1},
                        {"name": "m2", "return_type": "V", "params": [], "access_flags": 1},
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        m1_a = cls1.get_method("m1")
        m1_a_again = cls1.get_method("m1")
        m1_b = cls1.get_method("m2")
        m2_a = cls2.get_method("m1")

        assert m1_a is not None and m1_a_again is not None and m1_b is not None and m2_a is not None

        self.assertEqual(m1_a, m1_a_again)
        self.assertEqual(hash(m1_a), hash(m1_a_again))

        self.assertNotEqual(m1_a, m1_b)
        self.assertNotEqual(m1_a, m2_a)  # Different loader identity on defining class
        self.assertNotEqual(m1_a, "not_a_method")


class TestAnnotationDomainModel(unittest.TestCase):
    def test_empty_class_and_items_no_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Unannotated;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [{"name": "myField", "type": "I", "access_flags": 1}],
                    "virtual_methods": [
                        {
                            "name": "myMethod",
                            "return_type": "V",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": 1,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Unannotated"]

        self.assertEqual(cls.annotations, ())
        self.assertIsNone(cls.get_annotation("com.example.SomeAnn"))
        self.assertIsNone(cls.get_annotation("Lcom/example/SomeAnn;"))

        f = cls.get_field("myField")
        assert f is not None
        self.assertEqual(f.annotations, ())
        self.assertIsNone(f.get_annotation("com.example.SomeAnn"))

        m = cls.get_method("myMethod")
        assert m is not None
        self.assertEqual(m.annotations, ())
        self.assertEqual(m.parameter_annotations, ((), ()))
        self.assertIsNone(m.get_annotation("com.example.SomeAnn"))

    def test_class_annotations_visibility_types_and_elements(self) -> None:
        str_val = EncodedValue(value_arg=0, value_type=ValueType.STRING, value="hello")
        int_val = EncodedValue(value_arg=3, value_type=ValueType.INT, value=100)

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/AnnotatedClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "annotations": [
                        {
                            "type": "Lcom/example/RuntimeAnn;",
                            "visibility": AnnotationVisibility.RUNTIME,
                            "elements": {"val": str_val, "num": int_val},
                        },
                        {
                            "type": "Lcom/example/BuildAnn;",
                            "visibility": AnnotationVisibility.BUILD,
                            "elements": {},
                        },
                        {
                            "type": "Lcom/example/SystemAnn;",
                            "visibility": AnnotationVisibility.SYSTEM,
                            "elements": {},
                        },
                    ],
                },
                {
                    "name": "Lcom/example/RuntimeAnn;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.AnnotatedClass"]

        self.assertEqual(len(cls.annotations), 3)

        ann_runtime = cls.get_annotation("com.example.RuntimeAnn")
        self.assertIsNotNone(ann_runtime)
        assert ann_runtime is not None
        self.assertIsInstance(ann_runtime, Annotation)

        self.assertEqual(ann_runtime.type_descriptor, "Lcom/example/RuntimeAnn;")
        self.assertEqual(ann_runtime.type_name, "com.example.RuntimeAnn")

        self.assertEqual(ann_runtime.visibility, AnnotationVisibility.RUNTIME)
        self.assertTrue(ann_runtime.is_runtime)
        self.assertFalse(ann_runtime.is_build)
        self.assertFalse(ann_runtime.is_system)

        # Raw item access
        self.assertEqual(ann_runtime.raw.visibility, AnnotationVisibility.RUNTIME)

        # Mapping and MappingProxyType type conformity
        self.assertIsInstance(ann_runtime.elements, Mapping)
        self.assertIsInstance(ann_runtime.elements, MappingProxyType)

        # Immutability verification
        with self.assertRaises(TypeError):
            ann_runtime.elements["new_key"] = int_val  # type: ignore[index]

        with self.assertRaises(TypeError):
            del ann_runtime.elements["val"]  # type: ignore[index]

        # Element access
        self.assertEqual(len(ann_runtime), 2)
        self.assertIn("val", ann_runtime)
        self.assertIn("num", ann_runtime)
        self.assertNotIn("missing", ann_runtime)

        self.assertEqual(ann_runtime["val"].value_type, ValueType.STRING)
        num_val = ann_runtime.get("num")
        assert num_val is not None
        self.assertEqual(num_val.value, 100)
        self.assertIsNone(ann_runtime.get("missing"))
        default_ev = EncodedValue(value_arg=3, value_type=ValueType.INT, value=42)
        self.assertEqual(ann_runtime.get("missing", default_ev), default_ev)

        elem_keys = set(ann_runtime)
        self.assertEqual(elem_keys, {"val", "num"})

        self.assertEqual(str(ann_runtime), "@com.example.RuntimeAnn")
        self.assertEqual(repr(ann_runtime), "<Annotation '@com.example.RuntimeAnn'>")

        # Build & System annotations
        ann_build = cls.get_annotation("Lcom/example/BuildAnn;")
        assert ann_build is not None
        self.assertTrue(ann_build.is_build)
        self.assertFalse(ann_build.is_runtime)
        self.assertFalse(ann_build.is_system)

        ann_system = cls.get_annotation("com.example.SystemAnn")
        assert ann_system is not None
        self.assertTrue(ann_system.is_system)

    def test_field_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/FieldClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {
                            "name": "annotatedField",
                            "type": "I",
                            "access_flags": 1,
                            "annotations": [
                                {
                                    "type": "Lcom/example/FieldAnn;",
                                    "visibility": AnnotationVisibility.RUNTIME,
                                    "elements": {
                                        "name": EncodedValue(
                                            value_arg=0, value_type=ValueType.STRING, value="test"
                                        )
                                    },
                                }
                            ],
                        },
                        {"name": "plainField", "type": "I", "access_flags": 1},
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.FieldClass"]

        f_ann = cls.get_field("annotatedField")
        assert f_ann is not None
        self.assertEqual(len(f_ann.annotations), 1)
        ann = f_ann.get_annotation("com.example.FieldAnn")
        self.assertIsNotNone(ann)
        assert ann is not None
        self.assertEqual(ann.type_name, "com.example.FieldAnn")

        f_plain = cls.get_field("plainField")
        assert f_plain is not None
        self.assertEqual(f_plain.annotations, ())
        self.assertIsNone(f_plain.get_annotation("com.example.FieldAnn"))

    def test_method_and_parameter_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/MethodClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "annotatedMethod",
                            "return_type": "V",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": 1,
                            "annotations": [
                                {
                                    "type": "Lcom/example/MethodAnn;",
                                    "visibility": AnnotationVisibility.RUNTIME,
                                    "elements": {},
                                }
                            ],
                            "parameter_annotations": [
                                [
                                    {
                                        "type": "Lcom/example/ParamAnn;",
                                        "visibility": AnnotationVisibility.RUNTIME,
                                        "elements": {},
                                    }
                                ],
                                [],
                            ],
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.MethodClass"]

        m = cls.get_method("annotatedMethod")
        assert m is not None

        # Method annotations
        self.assertEqual(len(m.annotations), 1)
        m_ann = m.get_annotation("com.example.MethodAnn")
        self.assertIsNotNone(m_ann)

        # Parameter annotations
        param_anns = m.parameter_annotations
        self.assertEqual(len(param_anns), 2)
        self.assertEqual(len(param_anns[0]), 1)
        self.assertEqual(param_anns[0][0].type_name, "com.example.ParamAnn")
        self.assertEqual(param_anns[1], ())

    def test_annotation_equality_and_hashing(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "annotations": [
                        {
                            "type": "Lcom/example/Ann;",
                            "visibility": AnnotationVisibility.RUNTIME,
                            "elements": {
                                "v": EncodedValue(value_arg=3, value_type=ValueType.INT, value=1)
                            },
                        }
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        ann1 = cls1.annotations[0]
        ann1_again = cls1.annotations[0]
        ann2 = cls2.annotations[0]

        self.assertEqual(ann1, ann1_again)
        self.assertEqual(hash(ann1), hash(ann1_again))

        self.assertEqual(ann1, ann2)  # Identical annotations across loaders compare equal
        self.assertEqual(hash(ann1), hash(ann2))
        self.assertNotEqual(ann1, "not_an_annotation")


class TestCodeAndCFGDomainModel(unittest.TestCase):
    def test_code_instruction_properties_and_resolutions(self) -> None:
        # const-string v0, "Hello" (op=0x1a, v0, str@0)
        # const/4 v1, #1 (op=0x12, v1, #1)
        # if-eqz v1, +4 (op=0x38, v1, +4 code units -> pc 0x0002 + 4 = 0x0006)
        # return-void (op=0x0e)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000: const-string v0, string@0
            b"\x12\x10"  # 0002: const/4 v1, #1
            b"\x38\x01\x04\x00"  # 0003: if-eqz v1, +4 -> target_pc 0x0007
            b"\x0e\x00"  # 0005: return-void
            b"\x0e\x00"  # 0006: return-void
            b"\x0e\x00"  # 0007: return-void
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/CFGTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "testMethod",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.STATIC),
                            "registers_size": 2,
                            "ins_size": 1,
                            "outs_size": 0,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.CFGTest"]
        m = cls.get_method("testMethod")
        assert m is not None

        code = m.code
        self.assertIsNotNone(code)
        assert code is not None

        self.assertEqual(code.registers_size, 2)
        self.assertEqual(code.ins_size, 1)
        self.assertEqual(code.locals_size, 1)
        self.assertEqual(code.register_name(0), "v0")
        self.assertEqual(code.register_name(1), "p0")

        # Instruction queries
        self.assertIn(0, code)
        self.assertIn(2, code)
        self.assertNotIn(1, code)  # 1 is middle of 2-unit instruction
        self.assertNotIn("invalid", code)

        inst0 = code.at(0)
        self.assertEqual(inst0.pc, 0)
        self.assertEqual(inst0.next_pc, 2)
        self.assertEqual(inst0.code_units, 2)
        self.assertEqual(inst0.opcode, Opcode.CONST_STRING)
        self.assertEqual(inst0.mnemonic, "const-string")
        self.assertEqual(inst0.register_names, ("v0",))
        self.assertEqual(inst0.string_value, "I")  # String ID 0 in build_dex_bytes

        inst1 = code.at(2)
        self.assertEqual(inst1.literal, 1)

        inst2 = code.at(3)
        self.assertTrue(inst2.is_branch)
        self.assertTrue(inst2.is_conditional_branch)
        self.assertFalse(inst2.is_unconditional_branch)
        self.assertEqual(inst2.branch_offset, 4)
        self.assertEqual(inst2.target_pc, 7)

        # Basic Block CFG verification
        blocks = code.blocks
        self.assertEqual(len(blocks), 4)
        entry = code.entry_block
        self.assertTrue(entry.is_entry)
        self.assertEqual(entry.start_pc, 0)
        self.assertEqual(entry.end_pc, 5)
        self.assertEqual(len(entry), 3)
        self.assertEqual(entry.terminator.pc, 3)
        self.assertEqual(entry.terminator.opcode, Opcode.IF_EQZ)
        self.assertEqual(tuple(b.start_pc for b in entry.successors), (5, 7))

        # Disassembly string
        dis = code.disassemble()
        self.assertIn(".method", dis)
        self.assertIn("const-string", dis)

    def test_basic_block_and_code_no_getitem(self) -> None:
        code_bytes = b"\x0e\x00"  # 0000: return-void
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/NoGetItem;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.NoGetItem"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code
        block = code.entry_block

        # Confirm __getitem__ is NOT implemented on Code or BasicBlock
        with self.assertRaises(TypeError):
            _ = code[0]  # type: ignore[typeddict-item]
        with self.assertRaises(TypeError):
            _ = block[0]  # type: ignore[typeddict-item]

    def test_payload_decoupling_next_pcs_and_switch_cfg(self) -> None:
        from dexbuf.instructions import PackedSwitch, ReturnVoid
        from dexbuf.instructions.payloads import PackedSwitchPayload
        from dexbuf.types import BranchOffset, Reg

        # Build code stream with packed-switch, return-void, packed-switch-payload
        # PC 0: packed-switch v0, +4 (target payload is at PC 4)
        sw_insn = PackedSwitch(a=Reg(0), b=BranchOffset(4))
        ret_insn = ReturnVoid()
        payload = PackedSwitchPayload(first_key=0, targets=(BranchOffset(3), BranchOffset(12)))

        code_stream = (
            sw_insn.to_bytes()
            + ret_insn.to_bytes()
            + payload.to_bytes()
            + ret_insn.to_bytes()
            + ret_insn.to_bytes()
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/SwitchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_stream,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.SwitchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Verify instructions contains zero payloads
        self.assertTrue(
            all(not isinstance(inst.raw, PackedSwitchPayload) for inst in code.instructions)
        )

        # Verify payloads collection and lookup
        self.assertEqual(len(code.payloads), 1)
        self.assertIsInstance(code.payloads[0], PackedSwitchPayload)
        self.assertEqual(code.get_payload(4), payload)
        self.assertIsNone(code.get_payload(0))

        # Verify CodeInstruction.payload linking on referring switch instruction
        sw_code_inst = code.at(0)
        self.assertEqual(sw_code_inst.payload, payload)
        self.assertEqual(sw_code_inst.raw, sw_insn)

        # Verify CodeInstruction.next_pcs
        self.assertEqual(sw_code_inst.next_pcs, (3, 3, 12))
        ret_code_inst = code.at(3)
        self.assertEqual(ret_code_inst.next_pcs, ())

        # Verify basic block successors
        entry_block = code.entry_block
        succ_pcs = {succ.start_pc for succ in entry_block.successors}
        self.assertIn(3, succ_pcs)
        self.assertIn(12, succ_pcs)

    def test_straight_line_code_single_basic_block(self) -> None:
        # const-string v0, "Hello" (2 code units)
        # const/4 v1, #1 (1 code unit)
        # add-int v0, v0, v1 (1 code unit)
        # return-void (1 code unit)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000: const-string v0, string@0
            b"\x12\x10"  # 0002: const/4 v1, #1
            b"\x90\x00\x00\x01"  # 0003: add-int v0, v0, v1
            b"\x0e\x00"  # 0005: return-void
        )
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/StraightLineTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.StraightLineTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Entire method must form exactly 1 basic block containing all 4 instructions
        self.assertEqual(len(code.blocks), 1)
        block = code.entry_block
        self.assertTrue(block.is_entry)
        self.assertTrue(block.is_exit)
        self.assertEqual(block.start_pc, 0)
        self.assertEqual(block.end_pc, 6)
        self.assertEqual(len(block.instructions), 4)
        self.assertEqual(block.terminator.opcode, Opcode.RETURN_VOID)
        self.assertEqual(block.predecessors, ())
        self.assertEqual(block.successors, ())

    def test_unconditional_branch_and_catch_leaders(self) -> None:
        from dexbuf.instructions import Goto, ReturnVoid
        from dexbuf.types import BranchOffset

        # PC 0: const/4 v0, #0
        # PC 1: goto +3 -> PC 4
        # PC 3: return-void (unreachable/dead or target of jump)
        # PC 4: return-void
        goto_insn = Goto(a=BranchOffset(3))  # 1 unit, target_pc = 1 + 3 = 4
        ret_insn = ReturnVoid()  # 1 unit

        code_stream = (
            b"\x12\x00"  # 0000: const/4 v0, #0
            + goto_insn.to_bytes()  # 0001: goto +3 -> 0004
            + ret_insn.to_bytes()  # 0002: return-void
            + ret_insn.to_bytes()  # 0003: return-void
            + ret_insn.to_bytes()  # 0004: return-void
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/BranchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_stream,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.BranchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Leaders should be:
        # PC 0 (entry)
        # PC 2 (follower of goto)
        # PC 4 (target of goto)
        # PC 3 is follower of return-void at PC 2
        block0 = code.get_block_at(0)
        assert block0 is not None
        self.assertEqual(block0.start_pc, 0)
        self.assertEqual(block0.end_pc, 2)
        self.assertEqual(len(block0.instructions), 2)
        self.assertEqual(block0.terminator.mnemonic, "goto")

        succ_start_pcs = [b.start_pc for b in block0.successors]
        self.assertEqual(succ_start_pcs, [4])

    def test_field_and_method_disassemble(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/DisasmTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
                            ),
                            "value": EncodedValue(
                                value_arg=0, value_type=ValueType.STRING, value="MyTag"
                            ),
                        }
                    ],
                    "instance_fields": [
                        {
                            "name": "counter",
                            "type": "I",
                            "access_flags": int(AccessFlags.PRIVATE),
                        }
                    ],
                    "direct_methods": [
                        {
                            "name": "<init>",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR),
                            "code": b"\x0e\x00",  # return-void
                        }
                    ],
                    "virtual_methods": [
                        {
                            "name": "abstractMethod",
                            "return_type": "I",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.ABSTRACT),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.DisasmTest"]

        f_tag = cls.get_field("TAG")
        self.assertIsNotNone(f_tag)
        assert f_tag is not None
        self.assertEqual(
            f_tag.disassemble(),
            ".field public static final TAG:Ljava/lang/String; = 5",
        )

        f_counter = cls.get_field("counter")
        self.assertIsNotNone(f_counter)
        assert f_counter is not None
        self.assertEqual(f_counter.disassemble(), ".field private counter:I")

        m_init = cls.get_method("<init>")
        self.assertIsNotNone(m_init)
        assert m_init is not None
        m_init_dis = m_init.disassemble()
        self.assertTrue(m_init_dis.startswith(".method public constructor <init>()V"))
        self.assertIn(".registers", m_init_dis)
        self.assertIn("return-void", m_init_dis)

        m_abstract = cls.get_method("abstractMethod")
        self.assertIsNotNone(m_abstract)
        assert m_abstract is not None
        self.assertEqual(
            m_abstract.disassemble(),
            ".method public abstract abstractMethod()I",
        )

    def test_code_instruction_target_field_and_method_descriptors(self) -> None:
        from dexbuf.instructions import InvokeStaticRange, ReturnVoid, Sget
        from dexbuf.items import FieldIdItem, MethodIdItem
        from dexbuf.types import ArgumentCount, Idx, Reg

        code_bytes = (
            Sget(a=Reg(0), b=Idx[FieldIdItem](0)).to_bytes()
            + InvokeStaticRange(a=ArgumentCount(1), b=Idx[MethodIdItem](0), c=Reg(0)).to_bytes()
            + ReturnVoid().to_bytes()
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/TargetTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
                            ),
                        }
                    ],
                    "direct_methods": [
                        {
                            "name": "helper",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.STATIC),
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.TargetTest"].get_method("helper")
        self.assertIsNotNone(m)
        assert m is not None and m.code is not None

        inst0 = m.code.at(0)
        self.assertEqual(inst0.target_field_class_descriptor, "Lcom/example/TargetTest;")
        self.assertEqual(inst0.target_field_name, "TAG")
        self.assertEqual(inst0.target_field_type_descriptor, "Ljava/lang/String;")
        self.assertEqual(
            inst0.target_field_full_descriptor,
            "Lcom/example/TargetTest;->TAG:Ljava/lang/String;",
        )

        inst1 = m.code.at(2)
        self.assertEqual(inst1.target_method_class_descriptor, "Lcom/example/TargetTest;")
        self.assertEqual(inst1.target_method_name, "helper")
        self.assertEqual(inst1.target_method_descriptor, "(I)V")
        self.assertEqual(
            inst1.target_method_full_descriptor,
            "Lcom/example/TargetTest;->helper(I)V",
        )

        dis = m.code.disassemble()
        self.assertIn("sget v0, Lcom/example/TargetTest;->TAG:Ljava/lang/String;", dis)
        self.assertIn("invoke-static-range v0, Lcom/example/TargetTest;->helper(I)V", dis)

    def test_code_instruction_disassemble_forms(self) -> None:
        from dexbuf.instructions import Const4, ConstString, Goto, ReturnVoid
        from dexbuf.items import StringIdItem
        from dexbuf.types import BranchOffset, Idx, Literal, Reg

        c_str = ConstString(a=Reg(0), b=Idx[StringIdItem](0)).to_bytes()
        c_4 = Const4(a=Reg(1), b=Literal(1)).to_bytes()
        g_to = Goto(a=BranchOffset(2)).to_bytes()
        r_void = ReturnVoid().to_bytes()

        code_bytes = c_str + c_4 + g_to + r_void + r_void

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/InstDisasm;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "test",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.InstDisasm"].get_method("test")
        assert m is not None and m.code is not None

        # String instruction
        inst0 = m.code.at(0)
        self.assertEqual(inst0.disassemble(), '0000: const-string v0, "Lcom/example/InstDisasm;"')

        # Literal instruction
        inst2 = m.code.at(2)
        self.assertEqual(inst2.disassemble(), "0002: const-4 p0, #1")

        # Branch instruction with target_pc
        inst3 = m.code.at(3)
        self.assertEqual(inst3.disassemble(), "0003: goto # 0005")

        # Return void instruction
        inst5 = m.code.at(5)
        self.assertEqual(inst5.disassemble(), "0005: return-void")

    def test_exception_edges_and_handlers(self) -> None:
        from dexbuf import CatchEdge, CatchHandler

        # Build full code item with try/catch blocks using raw bytes
        # Try item covering PC 0000..0002 with handler at PC 0003
        # PC 0000: const/4 v0, #0
        # PC 0001: return-void
        # PC 0002: const/4 v0, #1
        # PC 0003: move-exception v0
        # PC 0004: return-void
        insns = b"\x12\x00\x0e\x00\x12\x10\x0d\x00\x0e\x00"

        # CodeItem header (16 bytes):
        # registers_size=2, ins_size=0, outs_size=0, tries_size=1, debug_info_off=0, insns_size=5
        header = struct.pack("<4H2I", 2, 0, 0, 1, 0, 5)
        # padding to 4 bytes offset: 16 + 10 = 26 -> 2 bytes padding to 28
        padding = b"\x00\x00"
        # TryItem (8 bytes): start_addr=0, insn_count=2, handler_off=1
        try_item = struct.pack("<IHH", 0, 2, 1)
        # CatchHandlerList:
        # encoded_catch_handler_list size = 1 (ULEB128 0x01)
        # handler at offset 1:
        # size = 1 (ULEB128 0x01) -> 1 typed handler
        # handler pair: type_idx=0 (ULEB128 0x00), addr=3 (ULEB128 0x03)
        # catch_all_addr: none (since size > 0 and no catch all)
        handlers = b"\x01\x01\x00\x03"

        full_code_bytes = header + insns + padding + try_item + handlers

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/TryCatchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": full_code_bytes,
                            "is_full_code_item": True,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.TryCatchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Basic blocks:
        # Block #0 [0..2] - protected block
        # Block #1 [2..3]
        # Block #2 [3..5] - catch handler block
        self.assertGreaterEqual(len(code.blocks), 3)

        block0 = code.get_block_at(0)
        assert block0 is not None
        self.assertEqual(len(block0.catch_edges), 1)

        edge = block0.catch_edges[0]
        self.assertIsInstance(edge, CatchEdge)
        self.assertIsInstance(edge.handler, CatchHandler)
        self.assertIs(edge.source_block, block0)
        self.assertEqual(edge.target_block.start_pc, 3)
        self.assertEqual(len(code.try_catches), 1)
        self.assertIs(edge.try_catch, code.try_catches[0])
        self.assertEqual(edge.target_pc, 3)
        self.assertEqual(edge.type_name, "com.example.TryCatchTest")

        self.assertEqual(block0.exception_successors, (edge.target_block,))
        self.assertEqual(block0.exception_handlers, (edge.handler,))

        handler_block = block0.exception_successors[0]
        self.assertTrue(handler_block.is_catch_handler)
        self.assertEqual(handler_block.incoming_catch_edges, (edge,))
        self.assertEqual(handler_block.exception_predecessors, (block0,))
        self.assertEqual(len(handler_block.handled_catches), 1)
        self.assertEqual(handler_block.handled_catches[0], edge.handler)
        self.assertEqual(handler_block.protected_blocks, (block0,))

        # Block disassembly formatting check with CFG comments
        dis = code.disassemble()
        self.assertIn("; preds:", dis)
        self.assertIn("; succs:", dis)
        self.assertNotIn("; preds: none", dis)
        self.assertNotIn("; succs: none", dis)

        # Block 0 has no normal predecessors or successors,
        # so neither ; preds: nor ; succs: should appear
        self.assertNotIn("; preds:", block0.disassemble())
        self.assertNotIn("; succs:", block0.disassemble())
        self.assertIn("; handler for: Lcom/example/TryCatchTest;", dis)
        self.assertIn("; catches: Lcom/example/TryCatchTest; -> #2", dis)

    def test_get_block_at_binary_search_and_boundaries(self) -> None:
        # const-string v0, "Hello" (op=0x1a, 2 code units: PC 0..2)
        # const/4 v1, #1          (op=0x12, 1 code unit:  PC 2..3)
        # if-eqz v1, +4           (op=0x38, 2 code units: PC 3..5, branch target PC 7)
        # return-void             (op=0x0e, 1 code unit:  PC 5..6)
        # const/4 v0, #2          (op=0x12, 1 code unit:  PC 6..7)
        # return-void             (op=0x0e, 1 code unit:  PC 7..8)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000..0002
            b"\x12\x10"  # 0002..0003
            b"\x38\x01\x04\x00"  # 0003..0005 (target 0007)
            b"\x0e\x00"  # 0005..0006
            b"\x12\x20"  # 0006..0007
            b"\x0e\x00"  # 0007..0008
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/GetBlockAtTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "testMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.GetBlockAtTest"].get_method("testMethod")
        assert m is not None and m.code is not None
        code = m.code

        # Verify block partitioning:
        # Leaders: 0 (entry), 5 (if-eqz fallthrough), 6 (return-void follower), 7 (if-eqz target)
        # Block #0: PC 0..5
        # Block #1: PC 5..6
        # Block #2: PC 6..7
        # Block #3: PC 7..8
        self.assertEqual(len(code.blocks), 4)
        b0, b1, b2, b3 = code.blocks
        self.assertEqual((b0.start_pc, b0.end_pc), (0, 5))
        self.assertEqual((b1.start_pc, b1.end_pc), (5, 6))
        self.assertEqual((b2.start_pc, b2.end_pc), (6, 7))
        self.assertEqual((b3.start_pc, b3.end_pc), (7, 8))

        # Boundary checks for Block #0 [0..5)
        self.assertIs(code.get_block_at(0), b0)  # start_pc
        self.assertIs(code.get_block_at(2), b0)  # middle PC (start of instruction)
        self.assertIs(code.get_block_at(4), b0)  # end_pc - 1

        # Boundary checks for Block #1 [5..6)
        self.assertIs(code.get_block_at(5), b1)  # start_pc and end_pc - 1

        # Boundary checks for Block #2 [6..7)
        self.assertIs(code.get_block_at(6), b2)  # start_pc and end_pc - 1

        # Boundary checks for Block #3 [7..8)
        self.assertIs(code.get_block_at(7), b3)  # start_pc and end_pc - 1

        # Out-of-bounds checks
        self.assertIsNone(code.get_block_at(-1))  # negative PC
        self.assertIsNone(code.get_block_at(8))  # at method end PC
        self.assertIsNone(code.get_block_at(100))  # far out-of-bounds PC


if __name__ == "__main__":
    unittest.main()
