-- R8 Protocol v0.2 dissector: private, experimental, closed-lab only.
-- Public wire framing only; SES ciphertext, keys, and plaintext are never decoded.

local r8 = Proto("R8", "R8 Protocol (experimental v0.2)")

local nh_names = { [1] = "CTL", [2] = "DGRAM", [3] = "SES", [59] = "NONE" }
local ctl_names = {
    [1] = "ECHO_REQUEST", [2] = "ECHO_REPLY",
    [128] = "DEST_UNREACHABLE", [129] = "TIME_EXCEEDED", [130] = "PACKET_TOO_BIG",
}

local f_version = ProtoField.uint8("r8.version", "Version", base.DEC, nil, 0xF0)
local f_profile = ProtoField.uint8("r8.profile", "Profile", base.DEC, nil, 0x0F)
local f_tc = ProtoField.uint8("r8.tc", "Traffic Class", base.HEX)
local f_plen = ProtoField.uint16("r8.plen", "Payload Length", base.DEC)
local f_nh = ProtoField.uint8("r8.nh", "Next Header", base.DEC, nh_names)
local f_hop = ProtoField.uint8("r8.hop", "Hop Limit", base.DEC)
local f_flags = ProtoField.uint8("r8.flags", "Flags", base.HEX)
local f_pslot = ProtoField.uint8("r8.pslot", "Path Slot", base.DEC)
local f_scid = ProtoField.uint64("r8.scid", "Session Context ID", base.HEX)
local f_src = ProtoField.bytes("r8.src", "Source LOC")
local f_dst = ProtoField.bytes("r8.dst", "Destination LOC")
local f_ctype = ProtoField.uint8("r8.ctl.type", "CTL Type", base.DEC, ctl_names)
local f_ccode = ProtoField.uint8("r8.ctl.code", "CTL Code", base.DEC)
local f_ccsum = ProtoField.uint16("r8.ctl.checksum", "CTL Checksum", base.HEX)
local f_cident = ProtoField.uint16("r8.ctl.identifier", "CTL Identifier", base.DEC)
local f_cseq = ProtoField.uint16("r8.ctl.sequence", "CTL Sequence", base.DEC)
local f_cmtu = ProtoField.uint32("r8.ctl.mtu", "CTL MTU", base.DEC)
local f_cquote = ProtoField.bytes("r8.ctl.quoted", "CTL Quoted Bytes")
local f_dsrc = ProtoField.uint16("r8.dgram.source_port", "DGRAM Source Port", base.DEC)
local f_ddst = ProtoField.uint16("r8.dgram.destination_port", "DGRAM Destination Port", base.DEC)
local f_dlen = ProtoField.uint16("r8.dgram.length", "DGRAM Length", base.DEC)
local f_dsum = ProtoField.uint16("r8.dgram.checksum", "DGRAM Checksum", base.HEX)
local f_stype = ProtoField.uint8("r8.ses.type", "SES Type", base.DEC)
local f_sversion = ProtoField.uint8("r8.ses.version", "SES Version", base.DEC)
local f_sprofile = ProtoField.uint8("r8.ses.profile", "SES Profile", base.DEC)
local f_sflags = ProtoField.uint8("r8.ses.flags", "SES Reserved Flags", base.HEX)
local f_error = ProtoField.string("r8.error", "R8 Error")
local e_invalid = ProtoExpert.new("r8.invalid", "Invalid R8 v0.2 packet", expert.group.MALFORMED, expert.severity.ERROR)

r8.fields = {
    f_version, f_profile, f_tc, f_plen, f_nh, f_hop, f_flags, f_pslot, f_scid, f_src, f_dst,
    f_ctype, f_ccode, f_ccsum, f_cident, f_cseq, f_cmtu, f_cquote,
    f_dsrc, f_ddst, f_dlen, f_dsum, f_stype, f_sversion, f_sprofile, f_sflags,
    f_error,
}
r8.experts = { e_invalid }

local function invalid(tree, message)
    tree:add(f_error, message:match("^([^:]+)"))
    tree:add_proto_expert_info(e_invalid, message)
end

local eth_type = Field.new("eth.type")
local ipv4_version = Field.new("ip.version")
local ipv6_version = Field.new("ipv6.version")

local function carrier_budget()
    local ether = eth_type()
    if ether and tonumber(ether) == 0x88b5 then return 1280 end
    if ipv6_version() then return 1232 end
    if ipv4_version() then return 1252 end
    return nil
end

local function checksum16(buffer, start, length, src, dst, nh)
    local sum = 0
    local function add16(value)
        sum = sum + value
        sum = bit.band(sum, 0xffff) + bit.rshift(sum, 16)
    end
    for offset = 0, 14, 2 do
        add16(src(offset, 2):uint())
        add16(dst(offset, 2):uint())
    end
    add16(bit.rshift(length, 16))
    add16(bit.band(length, 0xffff))
    add16(0)
    add16(nh)
    local offset = 0
    while offset + 1 < length do
        if (nh == 1 and offset == 2) or (nh == 2 and offset == 6) then
            add16(0)
        else
            add16(buffer(start + offset, 2):uint())
        end
        offset = offset + 2
    end
    if offset < length then add16(bit.lshift(buffer(start + offset, 1):uint(), 8)) end
    sum = bit.band(sum, 0xffff) + bit.rshift(sum, 16)
    local result = bit.band(bit.bnot(sum), 0xffff)
    if result == 0 then return 0xffff end
    return result
end

local function valid_ctl_code(ctype, code)
    if ctype == 1 or ctype == 2 or ctype == 129 then return code == 0 end
    if ctype == 128 then return code == 0 or code == 1 or code == 3 or code == 4 end
    return ctype == 130 and code == 0
end

local function ses_type_valid(typ)
    return typ >= 1 and typ <= 7
end

local function ses_flags_valid(typ, flags)
    return (typ >= 1 and typ <= 4 and flags == 0)
        or ((typ == 5 or typ == 6 or typ == 7) and flags == 0x01)
        or ((typ == 6 or typ == 7) and flags == 0x03)
end

local function ses_slot_valid(typ, profile, flags, slot)
    if typ >= 1 and typ <= 4 then return slot == 0 end
    if typ == 5 then return slot == 0 end
    if typ == 6 or typ == 7 then
        return (flags == 0x01 and slot == 0) or (profile == 3 and flags == 0x03 and slot == 1)
    end
    return false
end

function r8.dissector(buffer, pinfo, tree)
    local subtree = tree:add(r8, buffer(), "R8 Protocol (experimental v0.2)")
    if buffer:len() < 48 then
        invalid(subtree, "TRUNCATED: fixed header is 48 bytes")
        return buffer:len()
    end
    if buffer:len() > 1280 then
        invalid(subtree, "PACKET_CAP: serialized R8 packet exceeds 1280 bytes")
        return buffer:len()
    end
    local budget = carrier_budget()
    if budget and buffer:len() > budget then
        invalid(subtree, "BINDING_BUDGET: packet exceeds the carrier budget")
        return buffer:len()
    end

    local version_profile = buffer(0, 1):uint()
    local version, profile = bit.rshift(version_profile, 4), bit.band(version_profile, 0x0f)
    local plen, nh, hop, flags, slot = buffer(2, 2):uint(), buffer(4, 1):uint(), buffer(5, 1):uint(), buffer(6, 1):uint(), buffer(7, 1):uint()
    local scid_is_zero = buffer(8, 4):uint() == 0 and buffer(12, 4):uint() == 0
    local expected = 48 + plen
    if buffer:len() < expected then invalid(subtree, "TRUNCATED: payload is shorter than Payload Length") return buffer:len() end
    if buffer:len() > expected then invalid(subtree, "TRAILING_BYTES: packet exceeds Payload Length") return buffer:len() end
    if version ~= 8 then invalid(subtree, "VERSION: expected 8") return buffer:len() end
    if nh ~= 1 and nh ~= 2 and nh ~= 3 and nh ~= 59 then invalid(subtree, "NEXT_HEADER: unsupported value") return buffer:len() end
    if nh ~= 3 and profile > 3 then invalid(subtree, "PROFILE: reserved profile") return buffer:len() end
    if nh ~= 3 and buffer(1, 1):uint() ~= 0 then invalid(subtree, "TRAFFIC_CLASS: expected zero") return buffer:len() end
    if nh ~= 3 and hop == 0 then invalid(subtree, "HOP_LIMIT: expected nonzero") return buffer:len() end
    if nh ~= 3 and bit.band(flags, 0xfc) ~= 0 then invalid(subtree, "FLAGS: reserved bits set") return buffer:len() end

    if nh ~= 3 and profile ~= 0 then invalid(subtree, "PROFILE: non-SES requires profile zero") return buffer:len() end
    if nh ~= 3 and flags ~= 0 then invalid(subtree, "FLAGS: non-SES requires clear flags") return buffer:len() end
    if nh ~= 3 and slot ~= 0 then invalid(subtree, "PATH_SLOT: non-SES requires path slot zero") return buffer:len() end
    if nh ~= 3 and not scid_is_zero then invalid(subtree, "SCID: non-SES requires SCID zero") return buffer:len() end
    if nh == 59 and plen ~= 0 then invalid(subtree, "NONE_PAYLOAD: NONE requires an empty payload") return buffer:len() end

    subtree:add(f_version, buffer(0, 1)); subtree:add(f_profile, buffer(0, 1)); subtree:add(f_tc, buffer(1, 1)); subtree:add(f_plen, buffer(2, 2))
    subtree:add(f_nh, buffer(4, 1)); subtree:add(f_hop, buffer(5, 1)); subtree:add(f_flags, buffer(6, 1)); subtree:add(f_pslot, buffer(7, 1))
    subtree:add(f_scid, buffer(8, 8)); subtree:add(f_src, buffer(16, 16)); subtree:add(f_dst, buffer(32, 16))
    pinfo.cols.protocol = "R8"

    if nh == 1 then
        if plen < 4 then invalid(subtree, "CTL_SHORT: CTL header is four bytes") return buffer:len() end
        local ctype, code, checksum = buffer(48, 1):uint(), buffer(49, 1):uint(), buffer(50, 2):uint()
        if not ctl_names[ctype] then invalid(subtree, "CTL_TYPE: unknown type") return buffer:len() end
        if not valid_ctl_code(ctype, code) then invalid(subtree, "CTL_CODE: invalid code") return buffer:len() end
        local body_len = plen - 4
        local min_body = (ctype == 1 or ctype == 2 or ctype == 130) and 4 or 0
        if body_len < min_body or ((ctype == 128 or ctype == 129 or ctype == 130) and body_len - min_body > 512) then invalid(subtree, "CTL_BODY: invalid body length") return buffer:len() end
        if checksum == 0 or checksum16(buffer, 48, plen, buffer(16, 16), buffer(32, 16), nh) ~= checksum then invalid(subtree, "CTL_CHECKSUM: invalid checksum") return buffer:len() end
        local ctl = subtree:add(r8, buffer(48, plen), "CTL Message")
        ctl:add(f_ctype, buffer(48, 1)); ctl:add(f_ccode, buffer(49, 1)); ctl:add(f_ccsum, buffer(50, 2))
        if ctype == 1 or ctype == 2 then ctl:add(f_cident, buffer(52, 2)); ctl:add(f_cseq, buffer(54, 2)) end
        if ctype == 130 then ctl:add(f_cmtu, buffer(52, 4)) end
        if (ctype == 128 or ctype == 129) and body_len > 0 then ctl:add(f_cquote, buffer(52, body_len)) end
        if ctype == 130 and body_len > 4 then ctl:add(f_cquote, buffer(56, body_len - 4)) end
        pinfo.cols.info:set("R8-CTL " .. ctl_names[ctype])
    elseif nh == 2 then
        if plen < 8 then invalid(subtree, "DGRAM_SHORT: DGRAM header is eight bytes") return buffer:len() end
        local dlen, checksum = buffer(52, 2):uint(), buffer(54, 2):uint()
        if dlen ~= plen then invalid(subtree, "DGRAM_LENGTH: declared length must equal Payload Length") return buffer:len() end
        if checksum == 0 or checksum16(buffer, 48, plen, buffer(16, 16), buffer(32, 16), nh) ~= checksum then invalid(subtree, "DGRAM_CHECKSUM: invalid checksum") return buffer:len() end
        local dgram = subtree:add(r8, buffer(48, plen), "DGRAM Message")
        dgram:add(f_dsrc, buffer(48, 2)); dgram:add(f_ddst, buffer(50, 2)); dgram:add(f_dlen, buffer(52, 2)); dgram:add(f_dsum, buffer(54, 2))
        pinfo.cols.info:set("R8-DGRAM")
    elseif nh == 3 then
        if scid_is_zero then invalid(subtree, "SCID: SES requires a nonzero SCID") return buffer:len() end
        if plen < 4 then invalid(subtree, "TRUNCATED: SES envelope is four bytes") return buffer:len() end
        local typ, ses_version, ses_profile, ses_flags = buffer(48, 1):uint(), buffer(49, 1):uint(), buffer(50, 1):uint(), buffer(51, 1):uint()
        if not ses_type_valid(typ) or ses_version ~= 1 then invalid(subtree, "NEXT_HEADER: invalid SES type or version") return buffer:len() end
        if profile > 3 or ses_profile > 3 or ses_profile ~= profile then invalid(subtree, "PROFILE: invalid SES profile") return buffer:len() end
        if buffer(1, 1):uint() ~= 0 then invalid(subtree, "TRAFFIC_CLASS: expected zero") return buffer:len() end
        if hop == 0 then invalid(subtree, "HOP_LIMIT: expected nonzero") return buffer:len() end
        if bit.band(flags, 0xfc) ~= 0 or ses_flags ~= 0 or not ses_flags_valid(typ, flags) then invalid(subtree, "FLAGS: invalid SES flags") return buffer:len() end
        if not ses_slot_valid(typ, profile, flags, slot) then invalid(subtree, "PATH_SLOT: invalid SES path slot") return buffer:len() end
        local ses = subtree:add(r8, buffer(48, 4), "SES Public Envelope")
        ses:add(f_stype, buffer(48, 1)); ses:add(f_sversion, buffer(49, 1)); ses:add(f_sprofile, buffer(50, 1)); ses:add(f_sflags, buffer(51, 1))
        pinfo.cols.info:set("R8-SES public envelope")
    else
        pinfo.cols.info:set("R8-NONE")
    end
    return buffer:len()
end

DissectorTable.get("udp.port"):add(52808, r8)
DissectorTable.get("ethertype"):add(0x88B5, r8)
