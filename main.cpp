
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <memory>
#include <algorithm>

namespace logging {
    inline const char* file_basename(const char* path) {
        if (!path || !path[0]) return "?";
        const char* base = path;
        for (const char* p = path; *p; ++p) {
            if (*p == '/' || *p == '\\') base = p + 1;
        }
        return base;
    }

    struct rgb_t { int r, g, b; };

    inline rgb_t lerp_rgb_f(const rgb_t& a, const rgb_t& b, float t) {
        if (t <= 0.0f) return a;
        if (t >= 1.0f) return b;
        return {
            a.r + (int)((b.r - a.r) * t),
            a.g + (int)((b.g - a.g) * t),
            a.b + (int)((b.b - a.b) * t)
        };
    }

    inline float smooth_step(float t) {
        if (t <= 0.0f) return 0.0f;
        if (t >= 1.0f) return 1.0f;
        return t * t * (3.0f - 2.0f * t);
    }

    template<typename... Args>
    inline void print(const char* file_path, const char* format, Args... args) {
        static constexpr rgb_t k_blue = { 96, 168, 255 };
        static constexpr rgb_t k_purple = { 186, 118, 255 };

        const char* base = file_basename(file_path);
        size_t bn = strlen(base);
        size_t segments = bn + 2;

        for (size_t i = 0; i < segments; ++i) {
            float t = (segments <= 1) ? 0.5f : smooth_step((float)i / (float)(segments - 1));
            rgb_t c = lerp_rgb_f(k_blue, k_purple, t);
            if (i == 0) printf("\x1b[38;2;%d;%d;%dm[", c.r, c.g, c.b);
            else if (i == segments - 1) printf("\x1b[38;2;%d;%d;%dm]", c.r, c.g, c.b);
            else printf("\x1b[38;2;%d;%d;%dm%c", c.r, c.g, c.b, base[i - 1]);
        }
        printf("\x1b[0m ");

        char msg[4096];
        int n = snprintf(msg, sizeof(msg), format, args...);
        if (n < 0 || n >= (int)sizeof(msg)) {
            printf("\x1b[97m");
            printf(format, args...);
            printf("\x1b[0m\n");
            return;
        }

        size_t len = strlen(msg);
        while (len && (msg[len-1] == '\n' || msg[len-1] == '\r')) msg[--len] = '\0';

        char* split = nullptr;
        for (char* p = msg; *p; ++p) {
            if (*p == ':' && p[1] == ' ') { split = p; break; }
        }

        printf("\x1b[97m");
        if (split && split != msg) {
            *split = '\0';
            printf("%s: %s", msg, split + 2);
        } else {
            printf("%s", msg);
        }
        printf("\x1b[0m\n");
    }
}

inline bool try_set_font(const wchar_t* face, SHORT w, SHORT h) {
    HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h_out) return false;

    CONSOLE_FONT_INFOEX cfi{};
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = w;
    cfi.dwFontSize.Y = h;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcsncpy_s(cfi.FaceName, LF_FACESIZE, face, _TRUNCATE);
    return SetCurrentConsoleFontEx(h_out, FALSE, &cfi);
}

inline void set_font() {
    struct { const wchar_t* face; SHORT w, h; } candidates[] = {
        { L"Perfect DOS VGA 437", 9, 16 },
        { L"More Perfect DOS VGA", 9, 16 },
        { L"Fixedsys", 9, 15 },
        { L"Terminal", 6, 8 },
        { L"Cascadia Mono", 8, 16 },
        { L"Consolas", 8, 16 },
        { L"Lucida Console", 8, 12 },
    };
    for (auto& c : candidates) {
        if (try_set_font(c.face, c.w, c.h)) return;
    }
}

class c_memory {
public:
    c_memory(const std::string& process_name) {
        m_pid = get_pid(process_name);
        if (!m_pid) {
            logging::print(__FILE__, "failed to find process: %s", process_name.c_str());
            return;
        }

        m_process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, m_pid);
        if (!m_process_handle) {
            logging::print(__FILE__, "failed to open process: %s", process_name.c_str());
            return;
        }

        m_base_address = get_module_base(process_name);
        logging::print(__FILE__, "attached to %s (PID: %lu)", process_name.c_str(), m_pid);
    }

    ~c_memory() {
        if (m_process_handle) CloseHandle(m_process_handle);
    }

    bool valid() const { return m_process_handle != nullptr; }

    std::string find_username() {
        logging::print(__FILE__, "scanning memory...");

        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);

        uintptr_t addr = (uintptr_t)sys_info.lpMinimumApplicationAddress;
        uintptr_t max_addr = (uintptr_t)sys_info.lpMaximumApplicationAddress;
        int regions = 0;

        while (addr < max_addr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(m_process_handle, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
                addr += sys_info.dwPageSize;
                continue;
            }

            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
                size_t size = min(mbi.RegionSize, (SIZE_T)1024 * 1024 * 10);
                std::vector<char> buffer(size);
                SIZE_T bytes_read;

                if (ReadProcessMemory(m_process_handle, mbi.BaseAddress, buffer.data(), size, &bytes_read)) {
                    const char* pattern = "\"username\":\"";
                    size_t pattern_len = strlen(pattern);

                    for (size_t i = 0; i < bytes_read - pattern_len; i++) {
                        if (memcmp(&buffer[i], pattern, pattern_len) == 0) {
                            const char* start = &buffer[i] + pattern_len;
                            const char* end = start;

                            while (end < &buffer[bytes_read] && *end && *end != '"') end++;

                            if (end > start) {
                                size_t len = end - start;
                                if (len > 2 && len < 64) {
                                    std::string username(start, len);
                                    bool valid = true;
                                    for (char c : username) {
                                        if (c < 0x20 || c > 0x7E) { valid = false; break; }
                                    }
                                    if (valid && username.find("discord") == std::string::npos) {
                                        logging::print(__FILE__, "found: %s", username.c_str());
                                        return username;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            addr += mbi.RegionSize;
            regions++;
            if (regions % 1000 == 0) logging::print(__FILE__, "scanned %d regions", regions);
        }

        logging::print(__FILE__, "scan complete, nothing found");
        return "";
    }

private:
    DWORD m_pid{};
    HANDLE m_process_handle{};
    uintptr_t m_base_address{};

    DWORD get_pid(const std::string& name) {
        PROCESSENTRY32W entry{ sizeof(entry) };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        std::wstring wide(name.begin(), name.end());

        if (Process32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, wide.c_str()) == 0) {
                    DWORD pid = entry.th32ProcessID;
                    CloseHandle(snap);
                    return pid;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return 0;
    }

    uintptr_t get_module_base(const std::string& name) {
        MODULEENTRY32W entry{ sizeof(entry) };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        std::wstring wide(name.begin(), name.end());

        if (Module32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szModule, wide.c_str()) == 0) {
                    uintptr_t base = (uintptr_t)entry.modBaseAddr;
                    CloseHandle(snap);
                    return base;
                }
            } while (Module32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return 0;
    }
};

int main() {
    set_font();

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(out, &mode);
    SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    logging::print(__FILE__, "starting");

    auto mem = std::make_shared<c_memory>("Discord.exe");
    if (!mem->valid()) {
        logging::print(__FILE__, "failed to attach");
        return 1;
    }

    std::string username = mem->find_username();

    if (!username.empty()) {
        std::string title = "discord -> " + username;
        SetConsoleTitleA(title.c_str());
        logging::print(__FILE__, "username: %s", username.c_str());
    } else {
        SetConsoleTitleA("discord -> not found");
        logging::print(__FILE__, "no username found");
    }

    std::cin.get();
    return 0;
}
