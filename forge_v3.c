// forge.c v3.2 - in-process instrument for elretodeviktor.exe
// Builds on the proven v2 KeyAuth login forger and ADDS:
//   * force-load of winhttp/wininet/shell32 so it can be injected at process launch
//     (before those DLLs are loaded) and still hook them reliably.
//   * URL logging  (WinHttpConnect/OpenRequest, InternetConnectW, HttpOpenRequestW).
//   * payload dump (any non-KeyAuth HTTP response is written whole to C:\sh\dl_<n>.<ext>)
//     -> capture what the app downloads, whatever the format.
//   * exec logging  (CreateProcessW/A, WinExec, ShellExecuteExW) -> what the app runs.
//
// v3.1 FIX (SESION 13 bug): v3 forged the LOGIN body OVER the INIT response (both carry the
//   ownerid), wiping the real sessionid -> every post-login POST died with
//   "Session ID not provided". v3.1 distinguishes login vs init/check by the REQUEST:
//     - WinHttpSendRequest / WinHttpWriteData read the POST body; if it contains "type=login"
//       the request HANDLE is marked "login-pending".
//     - The read hook forges ONLY when the handle was login-pending AND the response does NOT
//       look like an init ("sessionid"/"Initialized"). The init/check responses pass UNTOUCHED
//       so the session stays alive and the spoofer proceeds to download/execute its payload.
//     - WinHttpCloseHandle clears the mark to avoid stale-handle reuse false positives.
//   Login bypass crypto is byte-for-byte the v2 winner. Logs to C:\sh\forge.log
#include <windows.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include "MinHook.h"

#pragma comment(lib, "bcrypt.lib")

typedef LPVOID HINTERNET;
#define HTTP_QUERY_CUSTOM 65535

static const char* SECRET  = "be5e6475eda666443f495db71cf8ef3385e849f218fe45eda190eb79fa4591f8";
static const char* OWNERID = "4c3UhKrXDj";

static const char* BODY_TMPL =
"{\"success\":true,\"message\":\"Logged in!\",\"info\":{\"username\":\"viktor\","
"\"subscriptions\":[{\"subscription\":\"default\",\"key\":\"FREE-REBOOTED-ACCESS-0001\","
"\"expiry\":\"4070908800\",\"timeleft\":2088000000}],\"ip\":\"127.0.0.1\",\"hwid\":null,"
"\"createdate\":\"1700000000\",\"lastlogin\":\"1700000000\"},\"nonce\":\"%s\",\"ownerid\":\"4c3UhKrXDj\"}";

static char g_body[1024];
static int  g_body_len = 0;
static char g_sig[80];
static int  g_have = 0;
static int  g_serving = 0;

static CRITICAL_SECTION g_cs;

static void logf(const char* fmt, ...) {
    EnterCriticalSection(&g_cs);
    FILE* f = fopen("C:\\sh\\forge.log", "a");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
        fprintf(f, "\n"); fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

// lossy wide->ascii for logging paths/urls
static void w2a(const wchar_t* w, char* out, int cap) {
    int i = 0; if (!w) { out[0]=0; return; }
    while (w[i] && i < cap-1) { out[i] = (w[i] < 128) ? (char)w[i] : '?'; i++; }
    out[i] = 0;
}

// length-bounded substring search (buffers are NOT null-terminated)
static int mem_contains(const void* hay, int haylen, const char* needle) {
    int nl = (int)strlen(needle);
    if (nl <= 0 || haylen < nl) return 0;
    const char* h = (const char*)hay;
    for (int i = 0; i + nl <= haylen; i++)
        if (memcmp(h + i, needle, nl) == 0) return 1;
    return 0;
}

static int hmac_sha256_hex(const char* key, int keylen, const unsigned char* data, int datalen, char* out) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    unsigned char digest[32]; int rc = -1;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return -1;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, keylen, 0) != 0) goto done;
    if (BCryptHashData(hHash, (PUCHAR)data, datalen, 0) != 0) goto done;
    if (BCryptFinishHash(hHash, digest, 32, 0) != 0) goto done;
    for (int i = 0; i < 32; i++) sprintf(out + i*2, "%02x", digest[i]);
    out[64] = 0; rc = 0;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

static int parse_keyauth(const char* buf, int len, char* nonce_out, int nonce_cap) {
    if (len <= 0 || len > 200000) return 0;
    static char tmp[262144];
    int n = len < (int)sizeof(tmp)-1 ? len : (int)sizeof(tmp)-1;
    memcpy(tmp, buf, n); tmp[n] = 0;
    int is_ka = (strstr(tmp, OWNERID) != NULL) || (strstr(tmp, "\"nonce\":\"") != NULL);
    nonce_out[0] = 0;
    char* p = strstr(tmp, "\"nonce\":\"");
    if (p) { p += 9; int i = 0; while (*p && *p != '\"' && i < nonce_cap-1) nonce_out[i++] = *p++; nonce_out[i] = 0; }
    return is_ka;
}

// true if a response body is an init/keepalive that MUST pass untouched (carries sessionid)
static int looks_like_init(const void* buf, int n) {
    return mem_contains(buf, n, "\"sessionid\"") || mem_contains(buf, n, "Initialized");
}

static void build_forge(const char* realbuf, int reallen) {
    char nonce[128] = "";
    parse_keyauth(realbuf, reallen, nonce, sizeof(nonce));
    if (!nonce[0]) { logf("BUILD_FORGE: nonce not found yet (chunked) - skip"); return; }
    g_body_len = snprintf(g_body, sizeof(g_body), BODY_TMPL, nonce);
    hmac_sha256_hex(SECRET, (int)strlen(SECRET), (const unsigned char*)g_body, g_body_len, g_sig);
    g_have = 1;
    logf("BUILD_FORGE nonce=%s body_len=%d sig=%s", nonce, g_body_len, g_sig);
}

// ---- login-request handle tracking (distinguish login vs init/check by the REQUEST) ----
static HINTERNET g_login_req[64];
static int       g_login_n = 0;

static void mark_login_req(HINTERNET h) {
    if (!h) return;
    EnterCriticalSection(&g_cs);
    int found = 0;
    for (int i = 0; i < g_login_n; i++) if (g_login_req[i] == h) { found = 1; break; }
    if (!found && g_login_n < 64) g_login_req[g_login_n++] = h;
    LeaveCriticalSection(&g_cs);
}
static int is_login_req(HINTERNET h) {
    int r = 0;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_login_n; i++) if (g_login_req[i] == h) { r = 1; break; }
    LeaveCriticalSection(&g_cs);
    return r;
}
static void clear_login_req(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_login_n; i++) if (g_login_req[i] == h) {
        g_login_req[i] = g_login_req[--g_login_n]; break;
    }
    LeaveCriticalSection(&g_cs);
}

// inspect a just-sent POST body; mark the handle if it is the login request
static void inspect_req_body(HINTERNET hReq, const void* body, int len) {
    if (!body || len <= 0) return;
    if (mem_contains(body, len, "type=login")) {
        mark_login_req(hReq);
        logf("REQ type=login on handle=%p (marked)", hReq);
    } else {
        char t[64] = "?";
        // log the type=... token for visibility (init/check/log/var/...)
        const char* b = (const char*)body;
        for (int i = 0; i + 5 <= len; i++) if (memcmp(b+i, "type=", 5) == 0) {
            int j = i + 5, k = 0;
            while (j < len && b[j] != '&' && k < 63) t[k++] = b[j++];
            t[k] = 0; break;
        }
        logf("REQ type=%s on handle=%p (pass)", t, hReq);
    }
}

// ---- payload dump map (capture downloaded executables / payloads) ----
typedef struct { HINTERNET h; FILE* f; int active; int wrote; } dlslot_t;
static dlslot_t g_dl[32];
static int g_dl_seq = 0;

// sniff a sensible extension from the first bytes of the response
static const char* sniff_ext(const unsigned char* b, DWORD n) {
    if (n >= 2 && b[0]=='M' && b[1]=='Z') return "exe";          // PE (exe/dll/sys)
    if (n >= 19 && memcmp(b, "Microsoft C/C++ MSF", 19) == 0) return "pdb";
    if (n >= 4 && memcmp(b, "PK\x03\x04", 4) == 0) return "zip";
    if (n >= 4 && memcmp(b, "\x7F""ELF", 4) == 0) return "elf";
    // all printable/whitespace in the first chunk -> treat as text
    int printable = 1, lim = n < 64 ? (int)n : 64;
    for (int i = 0; i < lim; i++) { unsigned char c = b[i];
        if (!(c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127))) { printable = 0; break; } }
    return printable ? "txt" : "bin";
}

// returns FILE* for this handle; opens a NEW dump on the first chunk of ANY download.
static FILE* dl_track(HINTERNET h, const unsigned char* buf, DWORD n) {
    EnterCriticalSection(&g_cs);
    FILE* res = NULL;
    for (int i = 0; i < 32; i++) if (g_dl[i].active && g_dl[i].h == h) { res = g_dl[i].f; break; }
    if (!res) {
        for (int i = 0; i < 32; i++) if (!g_dl[i].active) {
            const char* ext = sniff_ext(buf, n);
            char path[80]; int seq = ++g_dl_seq;
            snprintf(path, sizeof(path), "C:\\sh\\dl_%03d.%s", seq, ext);
            FILE* f = fopen(path, "wb");
            if (f) { g_dl[i].h = h; g_dl[i].f = f; g_dl[i].active = 1; g_dl[i].wrote = 0; res = f;
                     char sig[33]; int sl = n < 16 ? (int)n : 16;
                     for (int k=0;k<sl;k++) sprintf(sig+k*2, "%02x", buf[k]); sig[sl*2]=0;
                     logf("DL_OPEN  handle=%p -> %s (sig=%s)", h, path, sig); }
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
    return res;
}
static void dl_write(HINTERNET h, const void* buf, DWORD n) {
    FILE* f = dl_track(h, (const unsigned char*)buf, n);
    if (f) {
        EnterCriticalSection(&g_cs);
        fwrite(buf, 1, n, f); fflush(f);
        for (int i = 0; i < 32; i++) if (g_dl[i].active && g_dl[i].h == h) { g_dl[i].wrote += n; break; }
        LeaveCriticalSection(&g_cs);
    }
}
static void dl_close(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < 32; i++) if (g_dl[i].active && g_dl[i].h == h) {
        logf("DL_CLOSE handle=%p bytes=%d", h, g_dl[i].wrote);
        fclose(g_dl[i].f); g_dl[i].active = 0; g_dl[i].f = NULL; break;
    }
    LeaveCriticalSection(&g_cs);
}

// ---- WinHTTP read/forge hooks ----
typedef BOOL (WINAPI *t_ReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *t_QueryHeaders)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL (WINAPI *t_QDA)(HINTERNET,LPDWORD);
static t_ReadData     o_WinHttpReadData;
static t_QueryHeaders o_WinHttpQueryHeaders;
static t_QDA          o_WinHttpQueryDataAvailable;

static BOOL WINAPI h_WinHttpQueryDataAvailable(HINTERNET h, LPDWORD pAvail) {
    if (g_serving) { if (pAvail) *pAvail = 0; g_serving = 0; g_have = 0;
        logf("WH_QDA serving-end -> 0 (reset)"); return TRUE; }
    BOOL r = o_WinHttpQueryDataAvailable(h, pAvail);
    // only inflate for the login handle so its whole JSON arrives in one ReadData
    // (coalesces the chunked nonce). Init/check/download handles read naturally.
    if (r && pAvail && *pAvail > 0 && is_login_req(h)) { DWORD real = *pAvail; *pAvail = 0x10000;
        logf("WH_QDA login real=%lu -> 0x10000", real); }
    return r;
}

static BOOL WINAPI h_WinHttpReadData(HINTERNET h, LPVOID buf, DWORD toRead, LPDWORD pRead) {
    BOOL r = o_WinHttpReadData(h, buf, toRead, pRead);
    if (r && pRead) {
        DWORD n = *pRead;
        if (n > 0) {
            char snip[81]; int s = n < 80 ? n : 80; memcpy(snip, buf, s); snip[s] = 0;
            for (int i=0;i<s;i++) if ((unsigned char)snip[i] < 9) snip[i]='.';
            char nonce[128];
            int is_ka = parse_keyauth((const char*)buf, n, nonce, sizeof(nonce));
            if (is_ka) {
                int login = is_login_req(h);
                int init  = looks_like_init(buf, n);
                logf("WH_ReadData n=%lu KA login=%d init=%d snip=%s", n, login, init, snip);
                if (login && !init && nonce[0]) {
                    build_forge((const char*)buf, n);
                    if (g_have && g_body_len <= (int)toRead) {
                        memcpy(buf, g_body, g_body_len); *pRead = g_body_len; g_serving = 1;
                        clear_login_req(h);
                        logf("WH_ReadData >>> INJECTED login body %d (toRead=%lu)", g_body_len, toRead);
                    }
                }
                // any other KeyAuth response (init/check/...) passes through UNTOUCHED
            } else {
                logf("WH_ReadData n=%lu DL snip=%s", n, snip);
                dl_write(h, buf, n);          // capture non-keyauth downloads (any format)
            }
        } else {
            dl_close(h);                      // EOF for this handle
        }
    }
    return r;
}

static BOOL WINAPI h_WinHttpQueryHeaders(HINTERNET h, DWORD lvl, LPCWSTR name, LPVOID buf, LPDWORD plen, LPDWORD pidx) {
    BOOL r = o_WinHttpQueryHeaders(h, lvl, name, buf, plen, pidx);
    return r;
}

// ---- WinHTTP request/URL hooks ----
typedef HINTERNET (WINAPI *t_WHConnect)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *t_WHOpenReq)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *t_WHSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *t_WHWriteData)(HINTERNET,LPCVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *t_WHCloseHandle)(HINTERNET);
static t_WHConnect     o_WinHttpConnect;
static t_WHOpenReq     o_WinHttpOpenRequest;
static t_WHSendRequest o_WinHttpSendRequest;
static t_WHWriteData   o_WinHttpWriteData;
static t_WHCloseHandle o_WinHttpCloseHandle;

static HINTERNET WINAPI h_WinHttpConnect(HINTERNET s, LPCWSTR host, WORD port, DWORD f) {
    char hb[256]; w2a(host, hb, sizeof(hb));
    logf("WH_Connect host=%s port=%u", hb, port);
    return o_WinHttpConnect(s, host, port, f);
}
static HINTERNET WINAPI h_WinHttpOpenRequest(HINTERNET c, LPCWSTR verb, LPCWSTR obj, LPCWSTR ver, LPCWSTR ref, LPCWSTR* accept, DWORD flags) {
    char vb[16], ob[512]; w2a(verb, vb, sizeof(vb)); w2a(obj, ob, sizeof(ob));
    logf("WH_OpenRequest %s %s (flags=0x%lx)", vb[0]?vb:"GET", ob, flags);
    return o_WinHttpOpenRequest(c, verb, obj, ver, ref, accept, flags);
}
static BOOL WINAPI h_WinHttpSendRequest(HINTERNET hReq, LPCWSTR hdrs, DWORD hlen, LPVOID opt, DWORD optlen, DWORD total, DWORD_PTR ctx) {
    if (opt && optlen > 0) inspect_req_body(hReq, opt, (int)optlen);
    return o_WinHttpSendRequest(hReq, hdrs, hlen, opt, optlen, total, ctx);
}
static BOOL WINAPI h_WinHttpWriteData(HINTERNET hReq, LPCVOID buf, DWORD nbytes, LPDWORD pwritten) {
    if (buf && nbytes > 0) inspect_req_body(hReq, buf, (int)nbytes);
    return o_WinHttpWriteData(hReq, buf, nbytes, pwritten);
}
static BOOL WINAPI h_WinHttpCloseHandle(HINTERNET h) {
    clear_login_req(h);   // avoid stale-handle reuse false positives
    dl_close(h);
    return o_WinHttpCloseHandle(h);
}

// ---- WinINet hooks (downloads + telemetry; NO login forge here, login is WinHTTP) ----
typedef BOOL (WINAPI *t_InternetReadFile)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef HINTERNET (WINAPI *t_InetConnectW)(HINTERNET,LPCWSTR,WORD,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD_PTR);
typedef HINTERNET (WINAPI *t_HttpOpenReqW)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD,DWORD_PTR);
static t_InternetReadFile o_InternetReadFile;
static t_InetConnectW     o_InternetConnectW;
static t_HttpOpenReqW     o_HttpOpenRequestW;

static BOOL WINAPI h_InternetReadFile(HINTERNET h, LPVOID buf, DWORD toRead, LPDWORD pRead) {
    BOOL r = o_InternetReadFile(h, buf, toRead, pRead);
    if (r && pRead) {
        DWORD n = *pRead;
        if (n > 0) {
            char snip[81]; int s = n < 80 ? n : 80; memcpy(snip, buf, s); snip[s] = 0;
            for (int i=0;i<s;i++) if ((unsigned char)snip[i] < 9) snip[i]='.';
            char nonce[128];
            int is_ka = parse_keyauth((const char*)buf, n, nonce, sizeof(nonce));
            if (is_ka) {
                // login is on WinHTTP; never forge/clobber a KeyAuth response on WinINet
                logf("WI_ReadFile n=%lu KA(pass) snip=%s", n, snip);
            } else {
                logf("WI_ReadFile n=%lu DL snip=%s", n, snip);
                dl_write(h, buf, n);
            }
        } else { dl_close(h); }
    }
    return r;
}
static HINTERNET WINAPI h_InternetConnectW(HINTERNET s, LPCWSTR host, WORD port, LPCWSTR u, LPCWSTR p, DWORD svc, DWORD f, DWORD_PTR ctx) {
    char hb[256]; w2a(host, hb, sizeof(hb));
    logf("WI_Connect host=%s port=%u svc=%lu", hb, port, svc);
    return o_InternetConnectW(s, host, port, u, p, svc, f, ctx);
}

// v3.2: many WinINet downloads use InternetOpenUrl (no InternetConnect/HttpOpenRequest), so the URL
// was never logged AND keep-alive handle reuse concatenated different responses into one dump file.
// Hooking OpenUrl{W,A} logs the URL and flushes any stale dump on a recycled handle -> one file/request.
typedef HINTERNET (WINAPI *t_InetOpenUrlW)(HINTERNET,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD_PTR);
typedef HINTERNET (WINAPI *t_InetOpenUrlA)(HINTERNET,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *t_InetCloseHandle)(HINTERNET);
static t_InetOpenUrlW   o_InternetOpenUrlW;
static t_InetOpenUrlA   o_InternetOpenUrlA;
static t_InetCloseHandle o_InternetCloseHandle;

static HINTERNET WINAPI h_InternetOpenUrlW(HINTERNET hi, LPCWSTR url, LPCWSTR hdrs, DWORD hlen, DWORD flags, DWORD_PTR ctx) {
    char ub[1024]; w2a(url, ub, sizeof(ub));
    HINTERNET h = o_InternetOpenUrlW(hi, url, hdrs, hlen, flags, ctx);
    logf("WI_OpenUrlW url=%s -> handle=%p", ub, h);
    dl_close(h);   // flush any stale dump left on a recycled keep-alive handle
    return h;
}
static HINTERNET WINAPI h_InternetOpenUrlA(HINTERNET hi, LPCSTR url, LPCSTR hdrs, DWORD hlen, DWORD flags, DWORD_PTR ctx) {
    HINTERNET h = o_InternetOpenUrlA(hi, url, hdrs, hlen, flags, ctx);
    logf("WI_OpenUrlA url=%s -> handle=%p", url ? url : "", h);
    dl_close(h);
    return h;
}
static BOOL WINAPI h_InternetCloseHandle(HINTERNET h) {
    dl_close(h);
    clear_login_req(h);
    return o_InternetCloseHandle(h);
}
static HINTERNET WINAPI h_HttpOpenRequestW(HINTERNET c, LPCWSTR verb, LPCWSTR obj, LPCWSTR ver, LPCWSTR ref, LPCWSTR* accept, DWORD flags, DWORD_PTR ctx) {
    char vb[16], ob[512]; w2a(verb, vb, sizeof(vb)); w2a(obj, ob, sizeof(ob));
    logf("WI_OpenRequest %s %s", vb[0]?vb:"GET", ob);
    return o_HttpOpenRequestW(c, verb, obj, ver, ref, accept, flags, ctx);
}

// ---- execution hooks (what does the app run?) ----
typedef BOOL (WINAPI *t_CreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *t_CreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef UINT (WINAPI *t_WinExec)(LPCSTR,UINT);
typedef BOOL (WINAPI *t_ShellExecuteExW)(SHELLEXECUTEINFOW*);
static t_CreateProcessW  o_CreateProcessW;
static t_CreateProcessA  o_CreateProcessA;
static t_WinExec         o_WinExec;
static t_ShellExecuteExW o_ShellExecuteExW;

static BOOL WINAPI h_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD cf, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    char ab[512], cb[1024]; w2a(app, ab, sizeof(ab)); w2a(cmd, cb, sizeof(cb));
    logf("EXEC CreateProcessW app=[%s] cmd=[%s]", ab, cb);
    return o_CreateProcessW(app, cmd, pa, ta, inh, cf, env, dir, si, pi);
}
static BOOL WINAPI h_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD cf, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    logf("EXEC CreateProcessA app=[%s] cmd=[%s]", app?app:"", cmd?cmd:"");
    return o_CreateProcessA(app, cmd, pa, ta, inh, cf, env, dir, si, pi);
}
static UINT WINAPI h_WinExec(LPCSTR cmd, UINT show) {
    logf("EXEC WinExec cmd=[%s]", cmd?cmd:"");
    return o_WinExec(cmd, show);
}
static BOOL WINAPI h_ShellExecuteExW(SHELLEXECUTEINFOW* sei) {
    char fb[512], pb[1024];
    w2a(sei ? sei->lpFile : NULL, fb, sizeof(fb));
    w2a(sei ? sei->lpParameters : NULL, pb, sizeof(pb));
    logf("EXEC ShellExecuteExW file=[%s] params=[%s]", fb, pb);
    return o_ShellExecuteExW(sei);
}

static DWORD WINAPI init_thread(LPVOID p) {
    InitializeCriticalSection(&g_cs);
    CreateDirectoryA("C:\\sh", NULL);   // ensure dump/log dir exists
    logf("=== forge.dll v3.2 loaded, installing hooks ===");
    // ensure target modules are present even when injected at launch
    LoadLibraryA("winhttp.dll"); LoadLibraryA("wininet.dll"); LoadLibraryA("shell32.dll");
    if (MH_Initialize() != MH_OK) { logf("MH_Initialize FAIL"); return 0; }
    struct { const wchar_t* mod; const char* fn; void* det; void** orig; } H[] = {
        { L"winhttp", "WinHttpQueryDataAvailable", (void*)h_WinHttpQueryDataAvailable, (void**)&o_WinHttpQueryDataAvailable },
        { L"winhttp", "WinHttpReadData",     (void*)h_WinHttpReadData,     (void**)&o_WinHttpReadData },
        { L"winhttp", "WinHttpQueryHeaders", (void*)h_WinHttpQueryHeaders, (void**)&o_WinHttpQueryHeaders },
        { L"winhttp", "WinHttpConnect",      (void*)h_WinHttpConnect,      (void**)&o_WinHttpConnect },
        { L"winhttp", "WinHttpOpenRequest",  (void*)h_WinHttpOpenRequest,  (void**)&o_WinHttpOpenRequest },
        { L"winhttp", "WinHttpSendRequest",  (void*)h_WinHttpSendRequest,  (void**)&o_WinHttpSendRequest },
        { L"winhttp", "WinHttpWriteData",    (void*)h_WinHttpWriteData,    (void**)&o_WinHttpWriteData },
        { L"winhttp", "WinHttpCloseHandle",  (void*)h_WinHttpCloseHandle,  (void**)&o_WinHttpCloseHandle },
        { L"wininet", "InternetReadFile",    (void*)h_InternetReadFile,    (void**)&o_InternetReadFile },
        { L"wininet", "InternetConnectW",    (void*)h_InternetConnectW,    (void**)&o_InternetConnectW },
        { L"wininet", "HttpOpenRequestW",    (void*)h_HttpOpenRequestW,    (void**)&o_HttpOpenRequestW },
        { L"wininet", "InternetOpenUrlW",    (void*)h_InternetOpenUrlW,    (void**)&o_InternetOpenUrlW },
        { L"wininet", "InternetOpenUrlA",    (void*)h_InternetOpenUrlA,    (void**)&o_InternetOpenUrlA },
        { L"wininet", "InternetCloseHandle", (void*)h_InternetCloseHandle, (void**)&o_InternetCloseHandle },
        { L"kernel32","CreateProcessW",      (void*)h_CreateProcessW,      (void**)&o_CreateProcessW },
        { L"kernel32","CreateProcessA",      (void*)h_CreateProcessA,      (void**)&o_CreateProcessA },
        { L"kernel32","WinExec",             (void*)h_WinExec,             (void**)&o_WinExec },
        { L"shell32", "ShellExecuteExW",     (void*)h_ShellExecuteExW,     (void**)&o_ShellExecuteExW },
    };
    int N = (int)(sizeof(H)/sizeof(H[0]));
    for (int i=0;i<N;i++) {
        MH_STATUS st = MH_CreateHookApi(H[i].mod, H[i].fn, H[i].det, H[i].orig);
        logf("CreateHookApi %ls!%s -> %d", H[i].mod, H[i].fn, st);
    }
    logf("EnableHook -> %d", MH_EnableHook(MH_ALL_HOOKS));
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
    }
    return TRUE;
}
