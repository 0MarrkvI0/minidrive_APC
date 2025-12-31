# MiniDrive Architecture

## High-Level Components

- **Client (`client/`)**
  - Command-line interface with interactive shell and CLI parser.
  - Local filesystem manager for uploads/downloads/resume handling.
  - Synchronization engine for hashing, diffing, and incremental updates.
  - Transfer manager implementing chunked binary streaming over TCP.
- **Server (`server/`)**
  - Listener accepting TCP connections using Asio with a thread pool.
  - Session manager controlling public/private roots and single-session limits.
  - Command dispatcher with handlers for file/folder operations and sync APIs.
  - Persistence layer storing users, hashes, and resumable transfer metadata.
  - Filesystem executor guarded against path traversal using `std::filesystem`.
- **Shared (`shared/`)**
  - JSON protocol schema and serialization helpers using `nlohmann::json`.
  - Error code definitions and mapping utilities.
  - Cryptographic helpers leveraging libsodium for password hashing and file hashes.
  - Logging helpers wrapping `spdlog` (optional) and console fallbacks.

## Directory Layout

```
.
├── CMakeLists.txt            # Root build orchestrator
├── cmake/                    # Toolchain and dependency helpers
├── external/                 # Vendored single-header libraries (Asio, JSON)
├── client/
│   ├── src/main.cpp
│   └── CMakeLists.txt
├── server/
│   ├── include/
│   ├── src/main.cpp
│   └── CMakeLists.txt
├── common/
│   ├── meta.hpp # resume handler
│   ├── protocol.hpp # transfer handler
│   └── CMakeLists.txt
├── external/
│   └── Dependencies.cmake          // external lib
├── docs/                     # Documentation
│   ├── architecture.md
│   ├── protocol.md
│   └── requirements.md
└── README.md
```
