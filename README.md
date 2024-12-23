# SHA256-Lua

SHA256 hashing algorithm in pure Lua.

- Inspired from [lua-users: Secure Hash Algorithm](http://lua-users.org/wiki/SecureHashAlgorithm).
- Lua version: 5.4.x

## Usage Example (CLI)

```lua
local SHA256 = require("sha256")
::start::
io.write("Enter your message: ")
local msg = io.read("*l")
print(SHA256(msg))
goto start -- Prompt again unless keyboard-interrupted
```

> [!NOTE]
> Lua is not intended for cryptographic operations. If you want better performance, use LuaJIT or add your own C bindings.
