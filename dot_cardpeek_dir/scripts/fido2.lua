-- @name FIDO2
-- @description FIDO2/CTAP2 authenticators
-- @targets 0.8.4-win32

require('lib.apdu')
require('lib.cbor')
require('lib.strict')

local AID = "#A0000006472F0001"

local U2F_V2 = bytes.new(8, "55 32 46 5F 56 32")
local FIDO_2_0 = bytes.new(8, "46 49 44 4F 5F 32 5F 30")

local CLA = 0x80

local NFCCTAP_MSG = 0x10

-- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
local versions_alt = {
    ["U2F_V2"] = "CTAP1/U2F",
    ["FIDO_2_0"] = "CTAP2.0",
    ["FIDO_2_1_PRE"] = "CTAP2.1 Preview",
    ["FIDO_2_1"] = "CTAP2.1",
}

-- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-defined-extensions
local extensions_alt = {
    ["credProtect"] = "Credential Protection",
    ["credBlob"] = "Credential Blob",
    ["largeBlobKey"] = "Large Blob Key",
    ["minPinLength"] = "Minimum PIN Length",
    ["hmac-secret"] = "HMAC Secret",
}

-- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#option-id
local options_desc = {
    ["plat"] = {
        label = "Is Platform Device",
        alt = { [true] = "Yes", [false] = "No" } },
    ["rk"] = {
        label = "Has Key Storage",
        alt = { [true] = "Yes", [false] = "No" } },
    ["clientPin"] = {
        label = "Client PIN",
        alt = { [true] = "Set", [false] = "Not set" } },
    ["up"] = {
        label = "Can Test User Presence",
        alt = { [true] = "Yes", [false] = "No" } },
    ["uv"] = {
        label = "User Verification",
        alt = { [true] = "Configured", [false] = "Not configured" } },
    -- pinUvAuthToken
    -- noMcGaPermissionsWithClientPin
    -- largeBlobs
    -- ep
    -- bioEnroll
    -- userVerificationMgmtPreview
    -- uvBioEnroll
    -- authnrCfg
    -- uvAcfg
    -- credMgmt
    -- credentialMgmtPreview
    -- setMinPINLength
    -- makeCredUvNotRqd
    -- alwaysUv
}

-- https://www.w3.org/TR/webauthn/#enum-transport
local transports_alt = {
    ["usb"] = "USB",
    ["nfc"] = "NFC",
    ["ble"] = "BLE",
    ["internal"] = "Internal",
}

-- https://www.w3.org/TR/webauthn/#enum-credentialType
local algorithms_type_alt = {
    ["public-key"] = "Public key",
}

-- https://www.w3.org/TR/webauthn/#typedefdef-cosealgorithmidentifier
local algorithms_alg_alt = {
    [-7] = "ES256: ECDSA using P-256 and SHA-256",
    [-35] = "ES384: ECDSA using P-384 and SHA-384",
    [-36] = "ES512: ECDSA using P-521 and SHA-512",
    [-8] = "Ed25519: EdDSA using Curve25519 and SHA-512",
}

local function send_msg(data)
    -- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#nfc-framing
    -- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#nfc-fragmentation
    -- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#nfc-ctap-msg
    local frag_size = 255
    if #data > frag_size then
        local i = 0
        while #data - i > frag_size do
            local cmd = bytes.new(8, bit.OR(CLA, 0x10), NFCCTAP_MSG, 0x00, 0x00,
                                     0xFF, data:sub(i, i + frag_size - 1))
            local sw, rsp = card.send(cmd)
            if sw ~= 0x9000 then
                return sw, rsp
            end
            i = i + frag_size
        end
        data = data:sub(i, #data - 1)
    end
    local cmd = bytes.new(8, CLA, NFCCTAP_MSG, 0x00, 0x00, #data, data, 0x00)
    return card.send(cmd)
end

local function send_authenticatorGetInfo()
    local sw, rsp = send_msg(bytes.new(8, 0x04))
    if sw ~= 0x9000 then
        return sw, rsp
    end
    if #rsp < 1 then
        error("Invalid CTAP2 response.")
    end
    if #rsp == 1 then
        return rsp[0], nil
    else
        return rsp[0], cbor.decode(rsp, 1)
    end
end

local function analyze_ctap2(node)
    -- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#nfc-applet-selection
    local sw, rsp = card.select(AID, card.SELECT_RETURN_FIRST)
    if sw ~= 0x9000 then
        if sw == 0x6FFF then
            error("Failed to select FIDO applet.  On Windows, you may need to run cardpeek as administrator.")
        else
            error("Failed to select FIDO applet.")
        end
    end

    local app_node = node:append{
        classname = "application",
        label = "application",
        id = AID
    }

    app_node:append{
        label = "U2F Version",
        size = #rsp,
        val = rsp,
        alt = rsp:format("%P") }

    if rsp == U2F_V2 then
        -- CTAP1 and potentially CTAP2
    elseif rps == FIDO_2_0 then
        -- CTAP2 only
    else
        return
    end

    local sw, rsp = send_authenticatorGetInfo()
    if sw > 0xFF then
        -- No CTAP2
        return
    elseif sw ~= 0 then
        error("Error " .. sw .. " when requesting info.")
    end

    local versions = rsp[0x01]
    local versions_node = app_node:append{
        label = "Versions",
        id = "0x01" }
    for k, v in ipairs(versions) do
        versions_node:append{
            id = k,
            val = v,
            alt = versions_alt[v] }
    end

    local extensions = rsp[0x02]
    if extensions ~= nil then
        local extensions_node = app_node:append{
            label = "Extensions",
            id = "0x02" }
        for k, v in ipairs(extensions) do
            extensions_node:append{
                id = k,
                val = v,
                alt = extensions_alt[v] }
        end
    end

    local aaguid = rsp[0x03]
    app_node:append{
        label = "AAGUID",
        id = "0x03",
        size = #aaguid,
        val = aaguid,
        alt = aaguid:sub(0, 3):format("%D") .. "-" ..
              aaguid:sub(4, 5):format("%D") .. "-" ..
              aaguid:sub(6, 7):format("%D") .. "-" ..
              aaguid:sub(8, 9):format("%D") .. "-" ..
              aaguid:sub(10, 15):format("%D") }

    local options = rsp[0x04]
    if options ~= nil then
        local options_node = app_node:append{
            label = "Options",
            id = "0x04" }
        for k, v in pairs(options) do
            local desc = options_desc[k]
            options_node:append{
                label = desc and desc.label or k,
                id = desc and k or "",
                val = type(v) ~= "userdata" and tostring(v) or v,
                alt = desc and desc.alt[v] }
        end
    end

    local maxMsgSize = rsp[0x05]
    if maxMsgSize ~= nil then
        app_node:append{
            label = "Maximum Message Size",
            id = "0x05",
            val = maxMsgSize }
    end

    -- https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pin-uv-auth-protocol
    local pinUvAuthProtocols = rsp[0x06]
    if pinUvAuthProtocols ~= nil then
        local pinUvAuthProtocols_node = app_node:append{
            label = "PIN/UV Protocols",
            id = "0x06" }
        for k, v in ipairs(pinUvAuthProtocols) do
            pinUvAuthProtocols_node:append{
                id = k,
                val = v }
        end
    end

    local maxCredentialCountInList = rsp[0x07]
    if maxCredentialCountInList ~= nil then
        app_node:append{
            label = "Maximum Credentials Per List",
            id = "0x07",
            val = maxCredentialCountInList }
    end

    local maxCredentialIdLength = rsp[0x08]
    if maxCredentialIdLength ~= nil then
        app_node:append{
            label = "Maximum Credentials ID Length",
            id = "0x08",
            val = maxCredentialIdLength }
    end

    local transports = rsp[0x09]
    if transports ~= nil then
        local transports_node = app_node:append{
            label = "Transports",
            id = "0x09" }
        for k, v in ipairs(transports) do
            transports_node:append{
                id = k,
                val = v,
                alt = transports_alt[v] }
        end
    end

    local algorithms = rsp[0x0A]
    if algorithms ~= nil then
        local algorithms_node = app_node:append{
            label = "Algorithms",
            id = "0x0A" }
        for k, v in ipairs(algorithms) do
            local algorithm_node = algorithms_node:append{
                id = k }
            algorithm_node:append{
                label = "Type",
                id = "type",
                val = v.type,
                alt = algorithms_type_alt[v.type] }
            algorithm_node:append{
                label = "Algorithm",
                id = "alg",
                val = v.alg,
                alt = algorithms_alg_alt[v.alg] }
        end
    end

    -- maxSerializedLargeBlobArray (0x0B)
    -- forcePINChange (0x0C)
    -- minPINLength (0x0D)
    -- firmwareVersion (0x0E)
    -- maxCredBlobLength (0x0F)
    -- maxRPIDsForSetMinPINLength (0x10)
    -- preferredPlatformUvAttempts (0x11)
    -- uvModality (0x12)
    -- certifications (0x13)
    -- remainingDiscoverableCredentials (0x14)
    -- vendorPrototypeConfigCommands (0x15)
end

if card.connect() then
    local node = card.tree_startup("FIDO2")

    local okay, mess = pcall(analyze_ctap2, node)
    if not okay then
        log.print(log.ERROR, mess)
    end

    card.disconnect()
end
