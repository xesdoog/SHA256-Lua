# SHA256-Lua

SHA256 hashing algorithm in pure Lua.

Inspired from [lua-users: Secure Hash Algorithm](http://lua-users.org/wiki/SecureHashAlgorithm)

## Usage Example (CLI)

```lua
local SHA256 = require("sha256")
::start::
io.write("Enter your message: ")
local hash = io.read("*l")
print(SHA256(hash))
goto start -- Pprompt again unless keyboard-interrupted
```

> [!NOTE]
> Lua is not intended for cryptographic operations. If you want better performance, use LuaJIT or add your own C bindings.
