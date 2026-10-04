"""Synthetic DEX and VDEX binary builders for testing."""

import hashlib
import struct
import zlib
from typing import Any

from dexbuf.flags import AccessFlags
from dexbuf.items import (
    ClassDefItem,
    FieldIdItem,
    HeaderItem,
    MapList,
    MethodIdItem,
    ProtoIdItem,
    StringIdItem,
    TypeIdItem,
)
from dexbuf.leb128 import encode_uleb128
from dexbuf.mutf8 import encode_mutf8
from dexbuf.types import Count, Offset
from dexbuf.value import EncodedValue, ValueType


def _encode_uleb128(val: int) -> bytearray:
    return bytearray(encode_uleb128(val))


def _shorty_char(desc: str) -> str:
    if desc.startswith("L") or desc.startswith("["):
        return "L"
    return desc[0]


def _compute_shorty(return_desc: str, param_descs: list[str]) -> str:
    return _shorty_char(return_desc) + "".join(_shorty_char(p) for p in param_descs)


def create_minimal_dex_bytes() -> bytes:
    """Helper to construct minimal valid DEX header bytes (v035)."""
    magic = b"dex\n035\x00"
    checksum = 0x12345678
    signature = b"\x00" * 20
    file_size = HeaderItem.STRUCT.size  # 112 bytes
    header_size = HeaderItem.STRUCT.size
    endian_tag = 0x12345678

    header = HeaderItem(
        magic=magic,
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        link_size=0,
        link_off=Offset[Any](0),
        map_off=Offset[MapList](0),
        string_ids_size=Count[StringIdItem](0),
        string_ids_off=Offset[StringIdItem](0),
        type_ids_size=Count[TypeIdItem](0),
        type_ids_off=Offset[TypeIdItem](0),
        proto_ids_size=Count[ProtoIdItem](0),
        proto_ids_off=Offset[ProtoIdItem](0),
        field_ids_size=Count[FieldIdItem](0),
        field_ids_off=Offset[FieldIdItem](0),
        method_ids_size=Count[MethodIdItem](0),
        method_ids_off=Offset[MethodIdItem](0),
        class_defs_size=Count[ClassDefItem](0),
        class_defs_off=Offset[ClassDefItem](0),
        data_size=0,
        data_off=Offset[Any](0),
    )

    buf = bytearray(header_size)
    struct_format = HeaderItem.STRUCT
    struct_format.pack_into(
        buf,
        0,
        header.magic,
        header.checksum,
        header.signature,
        header.file_size,
        header.header_size,
        header.endian_tag,
        header.link_size,
        header.link_off,
        header.map_off,
        header.string_ids_size,
        header.string_ids_off,
        header.type_ids_size,
        header.type_ids_off,
        header.proto_ids_size,
        header.proto_ids_off,
        header.field_ids_size,
        header.field_ids_off,
        header.method_ids_size,
        header.method_ids_off,
        header.class_defs_size,
        header.class_defs_off,
        header.data_size,
        header.data_off,
    )
    return bytes(buf)


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
