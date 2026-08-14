-- R8 Protocol dissector (wire format v0.1)
-- Bindings: udp-binding = UDP port 52808, eth-binding = EtherType 0x88B5 (M4)
-- Install: Wireshark personal plugins folder, or `wireshark -X lua_script:r8.lua`

local r8 = Proto("R8", "R8 Protocol")

local nh_names = { [1] = "CTL", [2] = "DGRAM", [3] = "SES", [59] = "NONE" }
local ctl_names = {
    [1] = "ECHO_REQUEST", [2] = "ECHO_REPLY",
    [128] = "DEST_UNREACHABLE", [129] = "TIME_EXCEEDED", [130] = "PACKET_TOO_BIG",
}

local f_version = ProtoField.uint8 ("r8.version", "Version",       base.DEC, nil, 0xF0)
local f_profile = ProtoField.uint8 ("r8.profile", "Profile",       base.DEC, nil, 0x0F)
local f_tc      = ProtoField.uint8 ("r8.tc",      "Traffic Class", base.HEX)
local f_plen    = ProtoField.uint16("r8.plen",    "Payload Length", base.DEC)
local f_nh      = ProtoField.uint8 ("r8.nh",      "Next Header",   base.DEC, nh_names)
local f_hop     = ProtoField.uint8 ("r8.hop",     "Hop Limit",     base.DEC)
local f_flags   = ProtoField.uint8 ("r8.flags",   "Flags",         base.HEX)
local f_pslot   = ProtoField.uint8 ("r8.pslot",   "Path Slot",     base.DEC)
local f_scid    = ProtoField.uint64("r8.scid",    "Session Context ID", base.HEX)
local f_src     = ProtoField.bytes ("r8.src",     "Source LOC")
local f_dst     = ProtoField.bytes ("r8.dst",     "Destination LOC")
local f_ctype   = ProtoField.uint8 ("r8.ctl.type", "CTL Type", base.DEC, ctl_names)
local f_ccode   = ProtoField.uint8 ("r8.ctl.code", "CTL Code", base.DEC)
local f_ccsum   = ProtoField.uint16("r8.ctl.checksum", "CTL Checksum", base.HEX)

r8.fields = {
    f_version, f_profile, f_tc, f_plen, f_nh, f_hop, f_flags, f_pslot,
    f_scid, f_src, f_dst, f_ctype, f_ccode, f_ccsum,
}

function r8.dissector(buffer, pinfo, tree)
    if buffer:len() < 48 then return 0 end
    if bit.rshift(buffer(0,1):uint(), 4) ~= 8 then return 0 end
    pinfo.cols.protocol = "R8"
    local subtree = tree:add(r8, buffer(), "R8 Protocol, v8")
    subtree:add(f_version, buffer(0,1))
    subtree:add(f_profile, buffer(0,1))
    subtree:add(f_tc,      buffer(1,1))
    subtree:add(f_plen,    buffer(2,2))
    subtree:add(f_nh,      buffer(4,1))
    subtree:add(f_hop,     buffer(5,1))
    subtree:add(f_flags,   buffer(6,1))
    subtree:add(f_pslot,   buffer(7,1))
    subtree:add(f_scid,    buffer(8,8))
    subtree:add(f_src,     buffer(16,16))
    subtree:add(f_dst,     buffer(32,16))
    local nh = buffer(4,1):uint()
    if nh == 1 and buffer:len() >= 52 then
        local ctl = subtree:add(r8, buffer(48), "CTL Message")
        ctl:add(f_ctype, buffer(48,1))
        ctl:add(f_ccode, buffer(49,1))
        ctl:add(f_ccsum, buffer(50,2))
        local t = buffer(48,1):uint()
        if t == 1 then pinfo.cols.info:set("R8-ECHO request")
        elseif t == 2 then pinfo.cols.info:set("R8-ECHO reply") end
    elseif nh == 2 then
        pinfo.cols.info:set("R8-DGRAM")
    elseif nh == 3 then
        pinfo.cols.info:set("R8-SES")
    end
    return buffer:len()
end

DissectorTable.get("udp.port"):add(52808, r8)
DissectorTable.get("ethertype"):add(0x88B5, r8)
