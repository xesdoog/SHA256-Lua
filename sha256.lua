-- logical right shit
local function rshift(x, n)
  return (x >> n) & 0xFFFFFFFF
end

-- circular right shift
local function rrotate(x, n)
  return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
end

-- **SHA256 constants.**
--
-- First 32 bits of the fractional parts of the cube roots of the first
--
-- 64 primes (2..311)
local K = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
  0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
  0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
  0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
  0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
  0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
  0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
  0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
  0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
}

local function numToSOB(x, n)
  local s = ""
  for _ = 1, n do
    local remainder = x % 256
    s = string.char(remainder) .. s
    x = (x - remainder) / 256
  end
  return s
end

local function preprocess(msg, len)
  local ext = -(len + 1 + 8) % 64
  len = numToSOB(8 * len, 8)
  msg = msg .. "\128" .. string.rep("\0", ext) .. len
  assert(#msg % 64 == 0)
  return msg
end

local function sha256_compress(H, block)
  -- break chunk into sixteen 32-bit big-endian words W[0..15]
  local W = {}
  for i = 0, 15 do
    W[i] = ((block:byte(i * 4 + 1) << 24) | (block:byte(i * 4 + 2) << 16) |
      (block:byte(i * 4 + 3) << 8) | block:byte(i * 4 + 4)) & 0xFFFFFFFF
  end

  -- extend the sixteen 32-bit words into sixty-four 32-bit words W[16..63]
  for i = 16, 63 do
    local s0 = rrotate(W[i - 15], 7) ~ rrotate(W[i - 15], 18) ~ rshift(W[i - 15], 3)
    local s1 = rrotate(W[i - 2], 17) ~ rrotate(W[i - 2], 19) ~ rshift(W[i - 2], 10)
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF
  end

  -- initialize hash value for this chunk
  local a, b, c, d, e, f, g, h = table.unpack(H)

  -- main loop:
  for i = 0, 63 do
    local s1 = rrotate(e, 6) ~ rrotate(e, 11) ~ rrotate(e, 25)
    local ch = (e & f) ~ (~e & g)
    local t1 = (h + s1 + ch + K[i + 1] + W[i]) & 0xFFFFFFFF
    local s0 = rrotate(a, 2) ~ rrotate(a, 13) ~ rrotate(a, 22)
    local maj = (a & b) ~ (a & c) ~ (b & c)
    local temp2 = (s0 + maj) & 0xFFFFFFFF

    h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + temp2) & 0xFFFFFFFF
  end

  -- update hash values and truncate them to fit into 32-bits
  H[1] = (H[1] + a) & 0xFFFFFFFF
  H[2] = (H[2] + b) & 0xFFFFFFFF
  H[3] = (H[3] + c) & 0xFFFFFFFF
  H[4] = (H[4] + d) & 0xFFFFFFFF
  H[5] = (H[5] + e) & 0xFFFFFFFF
  H[6] = (H[6] + f) & 0xFFFFFFFF
  H[7] = (H[7] + g) & 0xFFFFFFFF
  H[8] = (H[8] + h) & 0xFFFFFFFF
end

local function SHA256(message)
  -- First 32 bits of the fractional parts of the square roots
  --
  -- of the first 8 primes W[1..18]
  local H = {
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19
  }

  -- pre-process the message
  message = preprocess(message, #message)

  -- process each 512-bit block
  for i = 1, #message, 64 do
    local block = message:sub(i, i + 63)
    sha256_compress(H, block)
  end

  -- return the final hash
  return string.format(
    "%08x%08x%08x%08x%08x%08x%08x%08x",
    H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
  )
end

return SHA256
