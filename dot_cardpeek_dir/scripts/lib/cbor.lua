cbor = cbor or {}

cbor.null = setmetatable({}, {
    __index = function() error("Attempt to index CBOR null.") end,
    __newindex = function() error("Attempt to index CBOR null.") end,
    __tostring = function() return "null" end,
})

function cbor.decode(data, i)
    if not (i < #data) then
        error("Unexpected end of data.")
    end
    
    local b = data[i]
    i = i + 1
    local major = bit.SHR(bit.AND(b, 0xE0), 5)
    local minor = bit.AND(b, 0x1F)

    local item
    if major == 0 or major == 1 then
        -- unsigned integer or negative integer
        if minor < 24 then
            item = minor
        elseif minor <= 27 then
            local item_size = bit.SHL(1, minor - 24)

            if #data - i < item_size then
                error("Unexpected end of data.")
            end

            local item = 0
            for j = 1, item_size do
                item = item * 0x100 + data[i]
                i = i + 1
            end
        else
            error("Invalid CBOR item at offset " .. i .. ".")
        end
        if major == 1 then
            item = -1 - item
        end
    elseif major == 2 or major == 3 then
        -- bytes or text
        local size
        if minor < 24 then
            size = minor
        elseif minor <= 27 then
            local size_size = bit.SHL(1, minor - 24)

            if #data - i < size_size then
                error("Unexpected end of data.")
            end

            size = 0
            for j in 1, size_size do
                size = size * 0x100 + data[i]
                i = i + 1
            end
        else
            -- indefinite size is not permitted
            error("Invalid CBOR item at offset " .. i .. ".")
        end

        if #data - i < size then
            error("Unexpected end of data.")
        end
        if size == 0 then
            item = bytes:new(8)
        else
            item = data:sub(i, i + size - 1)
            i = i + size
        end
        if major == 3 then
            item = item:format("%C")
        end
    elseif major == 4 then
        -- array
        local count
        if minor < 24 then
            count = minor
        elseif minor <= 27 then
            local count_size = bit.SHL(1, minor - 24)

            if #data - i < count_size then
                error("Unexpected end of data.")
            end

            count = 0
            for j in 1, count_size do
                count = count * 0x100 + data[i]
                i = i + 1
            end
        else
            -- indefinite count is not permitted
            error("Invalid CBOR item at offset " .. i .. ".")
        end

        item = {}
        for j = 1, count do
            local value
            value, i = cbor.decode(data, i)
            item[j] = value
        end
    elseif major == 5 then
        -- map
        local count
        if minor < 24 then
            count = minor
        elseif minor <= 27 then
            local count_size = bit.SHL(1, minor - 24)

            if #data - i < count_size then
                error("Unexpected end of data.")
            end

            count = 0
            for j in 1, count_size do
                count = count * 0x100 + data[i]
                i = i + 1
            end
        else
            -- indefinite count is not permitted
            error("Invalid CBOR item at offset " .. i .. ".")
        end

        item = {}
        for j = 1, count do
            local key, value
            key, i = cbor.decode(data, i)
            value, i = cbor.decode(data, i)
            item[key] = value
        end
    elseif major == 7 then
        -- simple/float
        if minor == 20 then
            item = false
        elseif minor == 21 then
            item = true
        elseif minor == 22 then
            item = cbor.null
        else
            error("Unsupported CBOR minor type " .. minor .. ".")
        end
    else
        error("Unsupported CBOR major type " .. major .. ".")
    end
    return item, i
end
