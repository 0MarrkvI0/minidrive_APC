How to run:
1. cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
2. cmake --build build
4. /build/server/server --port 5555 --root ./server/storage
3. ./build/client/client martin@127.0.0.1:6900 --log




AUTH username


0
resp.message == "LOGIN_SUCCESSFUL" || resp.message == "USER_REGISTERED" || resp.message == "PUBLIC_USER")
req.cmd = "LOGN";


1. AUTH
2. RESUME (DOWN/UP)
3. CMD


TESTS:

EXIT:
ako ked je  iny klien?

[client] Send request: EXIT
[client] Args: {}
[client] Received response: OK 0 GOODBYE
[client] Data: {}
Goodbye!

[server] Recieved request: EXIT
[server] Args: {}
[server] Send response: OK 0 GOODBYE
[server] Data: none
[server] Client disconnected.

HELP:

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

LIST:

[client] Send request: LIST
[client] Args: {}
[client] Received response: OK 1 START_LIST
[client] Data: {"size":60}
joj.png
transfer/
cucu.png
ahoj/
ahoj/kava.png
ahoj/nie.png

[client] Received response: OK 0 END_LIST
[client] Data: {}


[server] Recieved request: LIST
[server] Args: {}
[server] Send response: OK 1 START_LIST
[server] Data: {"size":60}

... bytestream ...

[server] Send response: OK 0 END_LIST
[server] Data: none


DELETE:

DELETE /workspaces/codespace_APC/server/storage/kevin/ahoj
[client] Send request: DELETE
[client] Args: {"path":"/workspaces/codespace_APC/server/storage/kevin/ahoj"}
[client] Received response: OK 0 DELETE_SUCCESS
[client] Data: {}

[server] Recieved request: DELETE
[server] Args: {"path":"/workspaces/codespace_APC/server/storage/kevin/ahoj"}
[server] Send response: OK 0 DELETE_SUCCESS
[server] Data: none


MOVE

MOVE ahoj/test.png /
[client] Send request: MOVE
[client] Args: {"dst":"/","src":"ahoj/test.png"}
[client] Received response: OK 0 MOVE_SUCCESS
[client] Data: {}

[server] Recieved request: MOVE
[server] Args: {"dst":"/","src":"ahoj/test.png"}
[server] Send response: OK 0 MOVE_SUCCESS
[server] Data: none