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