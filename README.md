# Short Lived Tokens - Read Me

A short lived token: built over RSA encryption-decryption (but can be extended) and UNIX timestamp working as a salt to build a very short-lived, practically
single time use token. Token expiry can be set as small as **100 milliseconds** but suggested to have a practical value of **2 to 5 seconds** over networked RPC on public cloud.

## Quick Setup

Use `pip install short_lived_tokens` to install the library.

## Usage

Here's a simple **example** to get you started.

```py
import os
import base64
from short_lived_tokens.endec.time_utils import get_timestamp_ms
import time
from short_lived_tokens.endec import RSAEndecEngine
from short_lived_tokens.token import Token

start_profile = time.time_ns()

TOKEN_LIFE_MS = 100

engine = RSAEndecEngine(token_life_ms=TOKEN_LIFE_MS)

if not os.path.exists('priv.pem') or not os.path.exists('pub.pem'):
    pubkey, privkey = engine.generate_keypair(4096)
    engine.save_key('priv.pem', privkey)
    engine.save_key('pub.pem', pubkey)


engine.load_key('priv.pem', set_priv=True)

encrypted_token = engine.encrypt("Hello")

print(encrypted_token.hex())

b64_auth_token = base64.b64encode(encrypted_token)

print(b64_auth_token)

token = Token(engine, b64_auth_token)

print(token.is_valid())

print('Sleeping...')

time.sleep(0.002)
print(token.is_valid(reset=True))

time.sleep(0.1)

print(token.is_valid(reset=True))

time.sleep(1)

print(token.is_valid(reset=True))

end_profile = time.time_ns()

print(f"Elapsed: {(end_profile - start_profile)/10**6} ms")
```

## TODOs

Django Wrapper for easy installation and usage with Django Framework.

---

**Contributers**

_Tushar Srivastava <<tusharsrivastava@friedbotstudio.com>>_
