# MiniDrive Protocol

MiniDrive uses a **single TCP connection per client** to exchange both
control messages and binary file data.

The protocol is intentionally simple and closely follows the current
implementation in `protocol.hpp` and `meta.hpp`.

---

## Overview

- **Transport:** TCP
- **Encoding:** UTF-8 (for control messages)
- **Connection model:** one TCP connection per client
- **Channels:**
  - Control Channel (JSON messages)
  - Data Channel (raw binary stream, same socket)

Control and data are exchanged sequentially on the same connection.
LIST and files are chunked (64kB) in Data channel 

---

## Authentification

### Public Mode
- Available to everyone without authentication.
- All unauthenticated clients operate in a shared **public directory** on the server.
- Files in public mode are visible to all users.
- Transfer resuming is **disabled** in public mode.

### Authenticated Users
- Users can authenticate using a **username and password**.
- Passwords are **never stored in plain text**.
- Each password is hashed using **SHA-256 with a unique salt** and stored in a simple **JSON-based database** on the server.
- After successful authentication, the user is assigned a **private directory** on the server.
- All file operations are strictly confined to the user’s private directory.

### Registration
- If a user attempts to log in with a username that does not exist, the client offers the option to **register a new account**.
- During registration:
  - The server securely hashes the password (with salt).
  - User credentials are persisted to disk.
  - A private directory for the new user is created automatically.

## Control Channel

### Message format

All control messages are encoded as **single-line JSON documents** and
terminated by a **newline character (`\n`)**.

The receiver reads messages using:

```
asio::read_until(socket, buffer, '\n')
```

### Request schema (Client → Server)

```json
{
  "cmd": "COMMAND",
  "args": { ... }
}
```

### Response schema (Server → Client)

```json
{
  "status": "OK",
  "code": 0,
  "message": "END_LIST",
  "data": {}
}
```

---

## Control ↔ Data sequencing

Some commands initiate a **data phase** after a control response.

Typical pattern:

1. Client sends control request (JSON)
2. Server replies with `OK / *_START`
3. **Binary data is streamed**
4. Server replies with `OK / *_END`

---

## Data Channel

- Binary data is sent over the **same TCP socket**
- There is **no per-chunk header**
- Receiver knows the number of bytes from metadata (`size`, `offset`) and `hash` for file integrity

---

```
COMMAND     ARGS                            COUNT
  ----------------------------------------------------
EXIT                                        0       
COPY        <src> <dst>                     2       
CD          <path>                          1       
MKDIR       <path>                          1       
DELETE      <path>                          1       
DOWNLOAD    <remote_path>  [local_path]     1-2     
RMDIR       <path>                          1       
UPLOAD      <local_path>  [remote_path]     1-2     
HELP                                        0       
MOVE        <src> <dst>                     2       
SYNC        <local_path> <remote_path>      2       
LIST         [path]                         0-1    
```
---

## File Upload (UPLOAD)

```json
{
  "cmd": "UPLOAD",
  "args": {
    "local_path": "/abs/path/file.bin",
    "remote_path": "/docs",
    "size": 12345,
    "hash": "sha256_<hex>",
    "offset": 0
  }
}
```

Server response:
```json
{ "status":"OK", "code":1, "message":"UPLOAD_START", "data":{} }
```

Client then streams `(size - offset)` bytes.

Completion:
```json
{ "status":"OK", "code":0, "message":"UPLOAD_END", "data":{} }
```


Example:
```
UPLOAD /workspaces/codespace_APC/aa.png
[client] Send request: UPLOAD
[client] Args: {"hash":"sha256_0abade102bfffe22a9abb06f9eaa22b19cb3704b5dc061403729e8879ae70177","local_path":"/workspaces/codespace_APC/aa.png","offset":0,"size":347958}
[client] Received response: OK 1 UPLOAD_START
[client] Data: {}
[send] chunk=65536 sent=65536 remaining=282422
[send] chunk=65536 sent=131072 remaining=216886
[send] chunk=65536 sent=196608 remaining=151350
[send] chunk=65536 sent=262144 remaining=85814
[send] chunk=65536 sent=327680 remaining=20278
[send] chunk=20278 sent=347958 remaining=0
[client] Received response: OK 0 UPLOAD_END
[client] Data: {}

[server] Recieved request: AUTH
[server] Args: {"username":"public"}
[server] Send response: OK 0 PUBLIC_USER
[server] Data: none
ALOHA
[server] Recieved request: UPLOAD
[server] Args: {"hash":"sha256_0abade102bfffe22a9abb06f9eaa22b19cb3704b5dc061403729e8879ae70177","local_path":"/workspaces/codespace_APC/aa.png","offset":0,"size":347958}
[server] Send response: OK 1 UPLOAD_START
[server] Data: none
[download] 100%
[server] Send response: OK 0 UPLOAD_END
[server] Data: none
```
---

## File Download (DOWNLOAD)

```json
{ "cmd":"DOWNLOAD", "args": { "remote_path": "/docs/file.bin" } }
```

Server response:
```json
{
  "status":"OK",
  "code":1,
  "message":"DOWNLOAD_START",
  "data":{
    "offset":0,
    "size":12345,
    "hash":"sha256_<hex>"
  }
}
```

Server streams binary data and finishes with:
```json
{ "status":"OK", "code":0, "message":"DOWNLOAD_END", "data":{} }
```

Example:
```
DOWNLOAD aa.png
Delete existing file [d] or choose other destination [c] or nothing [other keys]: d
[client] Send request: DOWNLOAD
[client] Args: {"force":true,"offset":0,"remote_path":"aa.png"}
[client] Received response: OK 1 DOWNLOAD_START
[client] Data: {"hash":"sha256_0abade102bfffe22a9abb06f9eaa22b19cb3704b5dc061403729e8879ae70177","offset":0,"size":347958}
[download] 100%
[client] Received response: OK 0 DOWNLOAD_END
[client] Data: {}

[server] Recieved request: DOWNLOAD
[server] Args: {"force":true,"offset":0,"remote_path":"aa.png"}
[server] Send response: OK 1 DOWNLOAD_START
[server] Data: {"hash":"sha256_0abade102bfffe22a9abb06f9eaa22b19cb3704b5dc061403729e8879ae70177","offset":0,"size":347958}
[send] chunk=65536 sent=65536 remaining=282422
[send] chunk=65536 sent=131072 remaining=216886
[send] chunk=65536 sent=196608 remaining=151350
[send] chunk=65536 sent=262144 remaining=85814
[send] chunk=65536 sent=327680 remaining=20278
[send] chunk=20278 sent=347958 remaining=0
[server] Send response: OK 0 DOWNLOAD_END
[server] Data: none
```

---

## LIST

```json
{ "cmd":"LIST", "args": { "path": "/docs" } }
```

Response sequence:
1. `START_LIST` with `{ "size": N }`
2. N bytes of text payload
3. `END_LIST`

Exmaple:
```
[client] Send request: LIST
[client] Args: {}
[client] Received response: OK 1 START_LIST
[client] Data: {"size":60}
j.png
transfer/
c.png
ahoj/
ahoj/kava.png
ahoj/nie.png

[client] Received response: OK 0 END_LIST
[client] Data: {}


[server] Recieved request: LIST
[server] Args: {}
[server] Send response: OK 1 START_LIST
[server] Data: {"size":60}
```

---

### SYNC

MiniDrive provides a **one-way directory synchronization** mechanism from the
client to the server.

The `SYNC` command synchronizes the contents of a **local directory**
with a **remote directory** on the server.


- Synchronization direction: **Local → Remote**
- Operates **recursively** on all nested subdirectories
- Uses **file hashes (SHA-256)** to detect changes
- Avoids re-uploading unchanged files
- Deletes files on the server that were removed locally
- Produces a summary of performed actions
- **UPLOAD** new or damaged files to server
- keep same dir structure


```
SYNC <local_path> <remote_path>
```

Output:
```
{
  "delete": 2,
  "skip": 0,
  "upload": 3
}
```

### Resume & Metadata

Transfers may be resumed using `.meta` files containing:

```json
{
  "type":"UPLOAD",
  "remote_path":"/server/file.bin.part",
  "local_path":"/client/file.bin",
  "file_size":12345,
  "file_hash":"sha256_<hex>",
  "offset":65536,
  "last_update":1735689600
}
```
Metadata is removed after successful completion.
.part file is created until stream ends, then is removed
After user login, server ask for resume (downloads + upload) and if (yes), all cmd are executed in resume time order (oldest first)

---

## Error Handling

All server responses follow a unified error model.

### Error Response Format

```json
{
  "status": "ERROR",
  "code": <numeric_error_code>,
  "message": "<short_error_identifier>",
  "data": { "message": "<optional details>" }
}

| Code | Meaning                                     |
| ---: | ------------------------------------------- |
|    0 | Success                                     |
|    1 | Start of streaming operation (`*_START`)    |
|  400 | Invalid request format or missing arguments |
|  401 | Authentication required / missing password  |
|  403 | Access denied / path outside user root      |
|  404 | File or directory not found                 |
|  405 | Invalid path type (file vs directory)       |
|  500 | Internal server error                       |
| 1001 | User not found                              |
| 1002 | Username already exists                     |
| 1003 | Invalid password                            |


## Session Model

- Each client establishes **exactly one TCP connection** to the server.
- One connection represents one **logical session**.
- Authentication state, working directory, and transfer metadata
  are bound to the lifetime of the TCP connection.
- On connection termination, the session state is discarded.


## Logging

- Client-side logging can be enabled using the `--log <file>` option.
- Logged information may include:
  - sent commands
  - server responses
  - transfer progress
  - error messages
- Logging is optional and does not affect protocol behavior.


## Connection Termination

- The client terminates a session by sending the `EXIT` command.
- The server responds with `OK / GOODBYE`.
- After the response, both sides close the TCP connection.
- Unexpected connection loss is treated as an interrupted session
  and may trigger transfer resuming if metadata is available.

## How to run:
1. cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
2. cmake --build build
4. /build/server/server --port 5555 --root ./server/storage
3. ./build/client/client m@127.0.0.1:6900 --log <file>

## Link to Github:
https://github.com/0MarrkvI0/minidrive_APC