-- @brief VxLan-GPE Protocol Dissector Plugin
-- @author Chason DU
-- @date 2017.08.14
-- @usage: copy this file to C:\Program Files\Wireshark\plugins\2.0.5
-- @reference:
--    https://tools.ietf.org/html/draft-quinn-vxlan-gpe-04
--    https://tools.ietf.org/html/draft-ietf-sfc-nsh-19
--    https://www.wireshark.org/docs/wsdg_html_chunked/index.html

-- Glocal variables
local nproto_table = {
    [0x1] = "IPv4",
    [0x2] = "IPv6",
    [0x3] = "Ethernet",
    [0x4] = "NSH",
    [0x5] = "MPLS"
}

-- create a new dissector
local NAME = "vxLan-gpe"
local PORT = 4790
local vxlan_gpe = Proto("VxLan-GPE", "VxLan-GPE Protocol")

-- create fields of vxlan_gpe
local fields = vxlan_gpe.fields
fields.flags    = ProtoField.uint8 (NAME .. ".flags",   "Flags", base.HEX)
fields.flag_i   = ProtoField.uint8 (NAME .. ".flag_i",  "VxLan Network ID", base.DEC, { [0] = "False", [1] = "True"}, 0x08)
fields.flag_n   = ProtoField.uint8 (NAME .. ".flag_n",  "Next Protocol", base.DEC, { [0] = "False", [1] = "True" }, 0x04)
fields.flag_r   = ProtoField.uint8 (NAME .. ".flag_r",  "Reserved (R)", base.DEC, nil, 0xF3)

fields.res1     = ProtoField.uint16(NAME .. ".res1",    "Reserved-1")
fields.nproto   = ProtoField.uint8 (NAME .. ".nproto",  "Next Protocol", base.HEX, nproto_table)
fields.vni      = ProtoField.uint24(NAME .. ".vni",     "VXLAN Network Identifier (VNI)")
fields.res2     = ProtoField.uint8 (NAME .. ".res2",    "Reserved-2")

-- create NSH dissector
local NAME_NSH = "nsh"
local nsh = Proto("NSH", "Network Service Header(NSH) Protocol")

-- create fields of nsh
local f_nsh = nsh.fields
local md_type_table = {
    [0x1] = "Fixed Length Context Header",
    [0x2] = "Variable Length Context Header"
}
f_nsh.ver   = ProtoField.uint16 (NAME_NSH .. ".ver",  "Version", base.DEC, nil, 0xC000)
f_nsh.flags = ProtoField.uint16 (NAME_NSH .. ".flags",  "Flags", base.HEX, nil, 0x3FC0)
f_nsh.len   = ProtoField.uint16 (NAME_NSH .. ".len",  "Length", base.DEC, nil, 0x003F)
f_nsh.md    = ProtoField.uint8  (NAME_NSH .. ".md",  "MD Type", base.HEX, md_type_table)
f_nsh.nproto= ProtoField.uint8  (NAME_NSH .. ".nproto",  "Next Protocol", base.HEX, nproto_table)
f_nsh.spath = ProtoField.uint24 (NAME_NSH .. ".spath",  "Service Path", base.DEC)
f_nsh.sindex= ProtoField.uint8  (NAME_NSH .. ".sindex",  "Service Index", base.DEC)
f_nsh.cxt0  = ProtoField.uint32 (NAME_NSH .. ".cxt0",  "Context-0", base.HEX)
f_nsh.cxt1  = ProtoField.uint32 (NAME_NSH .. ".cxt1",  "Context-1", base.HEX)
f_nsh.cxt2  = ProtoField.uint32 (NAME_NSH .. ".cxt2",  "Context-2", base.HEX)
f_nsh.cxt3  = ProtoField.uint32 (NAME_NSH .. ".cxt3",  "Context-3", base.HEX)

-- dissect packet sub-function
local function nsh_dissector (buf, pinfo, tree)
    local subtree = tree:add(nsh, buf())
    local offset = 0
    local buf_len = buf:len()

    -- show protocol name in protocol column
    pinfo.cols.protocol = nsh.name

    -- dissect field one by one, and add to protocol tree
    subtree:add(f_nsh.ver, buf(offset, 2))
    subtree:add(f_nsh.flags, buf(offset, 2))
    local nsh_len_4bytes = bit.band(buf(offset, 2):uint(), 0x3F)
    subtree:add(f_nsh.len, buf(offset, 2), (nsh_len_4bytes * 4)):append_text(" bytes ("..nsh_len_4bytes..")")
    offset = offset + 2

    subtree:add(f_nsh.md, buf(offset, 1))
    offset = offset + 1
    local nproto = buf(offset, 1)
    subtree:add(f_nsh.nproto, nproto)
    offset = offset + 1
    subtree:add(f_nsh.spath, buf(offset, 3))
    offset = offset + 3
    subtree:add(f_nsh.sindex, buf(offset, 1))
    offset = offset + 1

    subtree:add(f_nsh.cxt0, buf(offset, 4))
    offset = offset + 4
    subtree:add(f_nsh.cxt1, buf(offset, 4))
    offset = offset + 4
    subtree:add(f_nsh.cxt2, buf(offset, 4))
    offset = offset + 4
    subtree:add(f_nsh.cxt3, buf(offset, 4))
    offset = offset + 4
 
    local left_len = buf_len - offset;
    local left_buf = buf(offset):tvb()
    if (left_len > 0 and nproto:uint() == 0x1) then
        Dissector.get("ip"):call(left_buf, pinfo, tree)
    else
        Dissector.get("data"):call(left_buf, pinfo, tree)
    end
end

local function vxlan_flag_dissector(buf, pinfo, tree)
    local subtree = tree:add(fields.flags, buf())
    local flag = buf(offset, 1)

    subtree:add(fields.flag_i, flag)
    if (bit.band(flag:uint(), 0x80)) then
        subtree:append_text(", VxLan Network ID")
    end

    subtree:add(fields.flag_n, flag)
    if (bit.band(flag:uint(), 0x04)) then
        subtree:append_text(", Next Protocol")
    end 

    subtree:add(fields.flag_r, flag)
end

-- dissect packet main function
function vxlan_gpe.dissector (buf, pinfo, tree)
    local subtree = tree:add(vxlan_gpe, buf())
    local offset = 0
    local buf_len = buf:len()

    -- show protocol name in protocol column
    pinfo.cols.protocol = vxlan_gpe.name

    -- dissect field one by one, and add to protocol tree
    -- subtree:add(fields.flags, buf(offset, 1))
    vxlan_flag_dissector(buf(offset, 1), pinfo, subtree)
    offset = offset + 1
    subtree:add(fields.res1, buf(offset, 2))
    offset = offset + 2

    local nproto = buf(offset, 1)
    subtree:add(fields.nproto, nproto)
    subtree:append_text(", Next Protocol: " .. nproto:uint())
    offset = offset + 1

    subtree:add(fields.vni, buf(offset, 3))
    offset = offset + 3
    subtree:add(fields.res2, buf(offset, 1))
    offset = offset + 1

    local left_len = buf_len - offset;
    local left_buf = buf(offset):tvb()
    if (left_len > 0 and nproto:uint() == 0x04) then
        nsh_dissector(left_buf, pinfo, tree)
    else
        Dissector.get("data"):call(left_buf, pinfo, tree)
    end
end

-- register this dissector
DissectorTable.get("udp.port"):add(PORT, vxlan_gpe)

