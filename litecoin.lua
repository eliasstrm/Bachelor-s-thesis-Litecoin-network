litecoin_protocol = Proto("Litecoin", "Litecoin protocol")

-- Litecoin header
magic           = ProtoField.uint32("litecoin.magic", "magic", base.HEX)
message         = ProtoField.string("litecoin.message", "message", base.ASCII)
payload_length  = ProtoField.uint32("litecoin.length", "length", base.DEC)
checksum        = ProtoField.uint32("litecoin.checksum", "checksum", base.HEX)

-- Litecoin payload
payload         = ProtoField.string("litecoin.payload", "payload")

litecoin_protocol.fields = {magic, message, payload_length, checksum,	-- Header
payload																	-- Payload
}

function litecoin_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = litecoin_protocol.name

    local subtree           = tree:add(litecoin_protocol, buffer(), "Litecoin Data")
    local headerSubtree     = subtree:add(litecoin_protocol, buffer(), "Header")
    local payloadSubtree    = subtree:add(litecoin_protocol, buffer(), "Payload")

    local magics                = buffer(0,4):le_uint()
    local magic_description     = get_magic_name(magics)
    local messages              = buffer(4,12):stringz()
    local message_description   = get_message_name(messages)

    headerSubtree:add_le(magic,           buffer(0,4)):append_text(" (" .. magic_description .. ")")
    headerSubtree:add_le(message,         message_description)
    headerSubtree:add_le(payload_length,  buffer(16,4))
    headerSubtree:add_le(checksum,        buffer(20,4))
end

function get_magic_name(magic)
    local magic_description = "Unknown"

        if magic == 0xdbb6c0fb then magic_description = "MAIN"
    elseif magic == 0xdcb7c1fc then magic_description = "TESTNET" end
    
    return magic_description
end

function get_message_name(messages)
    local message_description = ""
        if messages == "version"        then message_description = "version"
    elseif messages == "verack"         then message_description = "verack"
    elseif messages == "addr"           then message_description = "addr"
    elseif messages == "inv"            then message_description = "inv"
    elseif messages == "getdata"        then message_description = "getdata"
    elseif messages == "merkleblock"    then message_description = "merkleblock"
    elseif messages == "getblocks"      then message_description = "getblocks"
    elseif messages == "getheaders"     then message_description = "getheaders"
    elseif messages == "tx"             then message_description = "tx"
    elseif messages == "headers"        then message_description = "headers"
    elseif messages == "block"          then message_description = "block"
    elseif messages == "getaddr"        then message_description = "getaddr"
    elseif messages == "mempool"        then message_description = "mempool"
    elseif messages == "ping"           then message_description = "ping"
    elseif messages == "pong"           then message_description = "pong"
    elseif messages == "notfound"       then message_description = "notfound"
    elseif messages == "filterload"     then message_description = "filterload"
    elseif messages == "filteradd"      then message_description = "filteradd"
    elseif messages == "filterclear"    then message_description = "filterclear"
    elseif messages == "reject"         then message_description = "reject"
    elseif messages == "sendheaders"    then message_description = "sendheaders"
    elseif messages == "feefilter"      then message_description = "feefilter"
    elseif messages == "sendcmpct"      then message_description = "sendcmpct"
    elseif messages == "cmpctblock"     then message_description = "cmpctblock"
    elseif messages == "getblocktxn"    then message_description = "getblocktxn"
    elseif messages == "blocktxn"       then message_description = "blocktxn"
    else message_description = "" end

    return message_description
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9333, litecoin_protocol)