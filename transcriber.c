#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/input.h>
#include <sound/asound.h>
#include <bearssl.h>
#include "ta.h"

enum {
    SAMPLE_RATE = 16000,
    INPUT_RATE = 48000,
    CHANNELS = 1,
    PCM_FRAMES = 1024,
    PRESS_MIN_MS = 300,
    PRESS_MAX_MS = 60000,
    MAX_WAV_DATA = 60u * 16000u * 2u,
    WAV_HDR_SIZE = 44,
    RESP_MAX = 8192,
    TEXT_MAX = 4096,
    HOST_MAX = 128,
    MODEL_MAX = 64,
    LANG_MAX = 16,
    EPATH_MAX = 192,
    APIKEY_MAX = 512,
    MAX_INPUT_DEVS = 8,
    MAX_REMOTES = 1,
};

static const int KEY_CODE = KEY_RIGHTCTRL;
#define BOUNDARY "wzp0boundary7f3a1c9e"
static const char MULTIPART_TAIL[] = "\r\n--" BOUNDARY "--\r\n";

static const uint16_t TLS_SUITES[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

typedef struct {
    char api_key[APIKEY_MAX];
    char host[HOST_MAX];
    char model[MODEL_MAX];
    char lang[LANG_MAX];
    char epath[EPATH_MAX];
} Config;

typedef struct {
    int channels;
    int32_t acc;
    int pending;
    int16_t raw[1024];
} Resampler;

typedef struct __attribute__((aligned(4096))) {
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    unsigned char iobuf[BR_SSL_BUFSIZE_MONO];
    char resp[RESP_MAX];
    char transcript[TEXT_MAX];
} TlsContext;

_Static_assert(sizeof(TlsContext) % 4096 == 0, "tls context must be page multiple");

static Config g_cfg = {
   .host = "api.groq.com",
   .model = "whisper-large-v3-turbo",
   .lang = "en",
   .epath = "/openai/v1/audio/transcriptions",
};

static TlsContext g_tls;
static struct sockaddr_storage g_remotes[MAX_REMOTES];
static socklen_t g_remote_lens[MAX_REMOTES];
static int g_remote_count = 0;

static Resampler g_resampler;
static char g_multipart_head[512];
static size_t g_multipart_head_len;

static const struct {
    const char *name;
    time_t expires;
} g_anchor_info[] = {
    {"ISRG Root X1", 2064567878},
    {"ISRG Root X2", 2231510400},
    {"GTS Root R4",  2097705600},
};

static ssize_t write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static void log_err(const char *s) {
    write_all(STDERR_FILENO, s, strlen(s));
}

static void fatal(const char *msg) {
    log_err("transcriber: ");
    log_err(msg);
    log_err("\n");
    _exit(1);
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool executable_in_path(const char *name) {
    const char *path = getenv("PATH");
    if (!path || !*path) path = "/usr/bin:/bin:/usr/local/bin";
    size_t name_len = strlen(name);
    const char *p = path;
    for (;;) {
        const char *colon = strchr(p, ':');
        size_t dir_len = colon ? (size_t)(colon - p) : strlen(p);
        if (dir_len > 0 && dir_len + name_len + 2 <= 256) {
            char full[256];
            memcpy(full, p, dir_len);
            full[dir_len] = '/';
            memcpy(full + dir_len + 1, name, name_len + 1);
            if (access(full, X_OK) == 0) return true;
        }
        if (!colon) break;
        p = colon + 1;
    }
    return false;
}

static bool contains_crlf(const char *s) {
    return strchr(s, '\r') != NULL || strchr(s, '\n') != NULL;
}
static bool has_control(const char *s) {
    for (const unsigned char *p = (const unsigned char*)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) return true;
    }
    return false;
}
static bool is_valid_host(const char *s) {
    if (!s || !*s) return false;
    if (contains_crlf(s) || has_control(s)) return false;
    if (strchr(s, '/') || strchr(s, ' ') || strchr(s, ':') || strchr(s, '@')) return false;
    size_t n = strlen(s);
    if (n >= HOST_MAX) return false;
    for (size_t i=0;i<n;i++) {
        char c = s[i];
        if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_')) return false;
    }
    return true;
}
static bool is_valid_token(const char *s, size_t max) {
    if (!s || !*s) return false;
    if (contains_crlf(s) || has_control(s)) return false;
    size_t n = strlen(s);
    if (n >= max) return false;

    for (size_t i=0;i<n;i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21 || c > 0x7E) return false;
        if (c == '"' || c == '\'' || c == ';') return false;
    }
    if (strstr(s, BOUNDARY)) return false;
    return true;
}
static bool is_valid_path(const char *s) {
    if (!s || !*s) return false;
    if (contains_crlf(s) || has_control(s)) return false;
    if (s[0] != '/') return false;
    size_t n = strlen(s);
    if (n >= EPATH_MAX) return false;
    if (strchr(s, ' ') || strchr(s, '"')) return false;
    if (strstr(s, BOUNDARY)) return false;
    return true;
}
static bool is_valid_apikey(const char *s) {
    if (!s || !*s) return false;
    if (contains_crlf(s) || has_control(s)) return false;
    size_t n = strlen(s);
    if (n >= APIKEY_MAX) return false;

    if (strchr(s, ' ') || strchr(s, '\t')) return false;
    return true;
}

static bool load_env_copy(const char *env, char *dst, size_t cap) {
    const char *v = getenv(env);
    if (!v || !*v) return false;
    size_t n = strlen(v);
    if (n >= cap) fatal("env value too long");
    memcpy(dst, v, n + 1);
    explicit_bzero((char *)v, n);
    unsetenv(env);
    return true;
}

static void config_load(void) {
    const char *k = getenv("TRANSCRIBE_API_KEY");
    if (!k || !*k) fatal("TRANSCRIBE_API_KEY not set");
    size_t n = strlen(k);
    if (n >= sizeof(g_cfg.api_key)) fatal("TRANSCRIBE_API_KEY too long");
    if (!is_valid_apikey(k)) fatal("TRANSCRIBE_API_KEY contains invalid chars (CRLF/control)");
    memcpy(g_cfg.api_key, k, n + 1);
    explicit_bzero((char *)k, n);
    unsetenv("TRANSCRIBE_API_KEY");

    char tmp_host[HOST_MAX];
    char tmp_model[MODEL_MAX];
    char tmp_lang[LANG_MAX];
    char tmp_epath[EPATH_MAX];
    bool has_host = false, has_model = false, has_lang = false, has_path = false;

    memcpy(tmp_host, g_cfg.host, sizeof(tmp_host));
    memcpy(tmp_model, g_cfg.model, sizeof(tmp_model));
    memcpy(tmp_lang, g_cfg.lang, sizeof(tmp_lang));
    memcpy(tmp_epath, g_cfg.epath, sizeof(tmp_epath));

    has_host = load_env_copy("TRANSCRIBE_HOST", tmp_host, sizeof(tmp_host));
    has_model = load_env_copy("TRANSCRIBE_MODEL", tmp_model, sizeof(tmp_model));
    has_lang = load_env_copy("TRANSCRIBE_LANGUAGE", tmp_lang, sizeof(tmp_lang));
    has_path = load_env_copy("TRANSCRIBE_PATH", tmp_epath, sizeof(tmp_epath));

    if (has_host && !is_valid_host(tmp_host)) fatal("TRANSCRIBE_HOST invalid (must be hostname, no CRLF/control)");
    if (has_model && !is_valid_token(tmp_model, sizeof(tmp_model))) fatal("TRANSCRIBE_MODEL invalid (CRLF/control/boundary)");
    if (has_lang && !is_valid_token(tmp_lang, sizeof(tmp_lang))) fatal("TRANSCRIBE_LANGUAGE invalid");
    if (has_path && !is_valid_path(tmp_epath)) fatal("TRANSCRIBE_PATH invalid (must start with /, no CRLF/control)");

    memcpy(g_cfg.host, tmp_host, sizeof(g_cfg.host));
    memcpy(g_cfg.model, tmp_model, sizeof(g_cfg.model));
    memcpy(g_cfg.lang, tmp_lang, sizeof(g_cfg.lang));
    memcpy(g_cfg.epath, tmp_epath, sizeof(g_cfg.epath));
}

static void disable_core_dumps(void) {
    struct rlimit rl = {0,0};
    setrlimit(RLIMIT_CORE, &rl);
#ifdef PR_SET_DUMPABLE
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    if (mlock(&g_cfg, sizeof(g_cfg)) != 0) {

        log_err("transcriber: warning: mlock failed for api key (no memlock limit?)\n");
    }
}

static void secure_wipe_cfg(void) {
    explicit_bzero(g_cfg.api_key, sizeof(g_cfg.api_key));
}

static void check_anchor_expiry(void) {
    time_t now = time(NULL);
    for (size_t i=0;i<sizeof(g_anchor_info)/sizeof(g_anchor_info[0]);i++) {
        time_t exp = g_anchor_info[i].expires;
        if (now >= exp) {
            char buf[256];
            snprintf(buf, sizeof(buf), "transcriber: CRITICAL: pinned anchor %s EXPIRED", g_anchor_info[i].name);
            log_err(buf); log_err("\n");
        }
    }
}

static void wav_fill_header(uint8_t hdr[WAV_HDR_SIZE], uint32_t data_len) {
    uint32_t riff_len = 36 + data_len;
    uint32_t fmt_len = 16;
    uint32_t sr = SAMPLE_RATE;
    uint32_t byte_rate = SAMPLE_RATE * CHANNELS * 2;
    uint16_t fmt = 1, ch = CHANNELS, bits = 16, block = CHANNELS * 2;
    memcpy(hdr + 0, "RIFF", 4);
    memcpy(hdr + 4, &riff_len, 4);
    memcpy(hdr + 8, "WAVEfmt ", 8);
    memcpy(hdr + 16, &fmt_len, 4);
    memcpy(hdr + 20, &fmt, 2);
    memcpy(hdr + 22, &ch, 2);
    memcpy(hdr + 24, &sr, 4);
    memcpy(hdr + 28, &byte_rate, 4);
    memcpy(hdr + 32, &block, 2);
    memcpy(hdr + 34, &bits, 2);
    memcpy(hdr + 36, "data", 4);
    memcpy(hdr + 40, &data_len, 4);
}

static ssize_t resample_read(int pcm_fd, Resampler *rs, int16_t *out, size_t cap) {
    ssize_t r;
    do { r = read(pcm_fd, rs->raw, sizeof(rs->raw)); } while (r < 0 && errno == EINTR);
    if (r <= 0) return r;

    int32_t acc = rs->acc;
    int pending = rs->pending;
    size_t written = 0;

    if (rs->channels == 1) {
        size_t samples = (size_t)r / 2;
        size_t i = 0;
        while (pending && i < samples && written < cap) {
            acc += rs->raw[i++];
            if (++pending == 3) { out[written++] = (int16_t)(acc / 3); acc = 0; pending = 0; }
        }
        while (i + 3 <= samples && written < cap) {
            int32_t s = (int32_t)rs->raw[i] + rs->raw[i+1] + rs->raw[i+2];
            out[written++] = (int16_t)(s / 3);
            i += 3;
        }
        while (i < samples && written < cap) { acc += rs->raw[i++]; pending++; }
    } else {
        size_t frames = (size_t)r / 4;
        int16_t *s = rs->raw;
        size_t i = 0;
        while (pending && i < frames && written < cap) {
            acc += (s[2*i] + s[2*i+1]) / 2;
            i++;
            if (++pending == 3) { out[written++] = (int16_t)(acc / 3); acc = 0; pending = 0; }
        }
        while (i + 3 <= frames && written < cap) {
            int32_t m0 = (s[2*i] + s[2*i+1]) / 2;
            int32_t m1 = (s[2*i+2] + s[2*i+3]) / 2;
            int32_t m2 = (s[2*i+4] + s[2*i+5]) / 2;
            out[written++] = (int16_t)((m0 + m1 + m2) / 3);
            i += 3;
        }
        while (i < frames && written < cap) { acc += (s[2*i] + s[2*i+1]) / 2; i++; pending++; }
    }

    rs->acc = acc;
    rs->pending = pending;
    return (ssize_t)(written * 2);
}

static int alsa_hw_configure(int fd, int channels) {
    struct snd_pcm_hw_params p = {0};
    for (int i = 0; i < 3; i++) for (int w = 0; w < 8; w++) p.masks[i].bits[w] = ~0u;
    for (int i = 0; i < 12; i++) { p.intervals[i].min = 0; p.intervals[i].max = ~0u; }
    p.masks[0].bits[0] = 1u << SNDRV_PCM_ACCESS_RW_INTERLEAVED;
    p.masks[1].bits[0] = 1u << SNDRV_PCM_FORMAT_S16_LE;
    p.masks[2].bits[0] = 1u << SNDRV_PCM_SUBFORMAT_STD;
    for (int w = 1; w < 8; w++) p.masks[0].bits[w] = p.masks[1].bits[w] = p.masks[2].bits[w] = 0;
    p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].max = 16;
    p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].max = 16 * channels;
    p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].max = (unsigned)channels;
    p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].min = p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].max = INPUT_RATE;
    for (int i = 0; i < 12; i++) p.intervals[i].integer = 1;
    p.intervals[SNDRV_PCM_HW_PARAM_TICK_TIME-8].integer = 0;
    p.rmask = (1u<<SNDRV_PCM_HW_PARAM_ACCESS)|(1u<<SNDRV_PCM_HW_PARAM_FORMAT)|(1u<<SNDRV_PCM_HW_PARAM_SUBFORMAT)
            |(1u<<SNDRV_PCM_HW_PARAM_SAMPLE_BITS)|(1u<<SNDRV_PCM_HW_PARAM_FRAME_BITS)
            |(1u<<SNDRV_PCM_HW_PARAM_CHANNELS)|(1u<<SNDRV_PCM_HW_PARAM_RATE);

    if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &p)!= 0) return -1;
    unsigned buf = p.intervals[SNDRV_PCM_HW_PARAM_BUFFER_SIZE-8].max;
    if (buf < 16) buf = 16;

    struct snd_pcm_sw_params s = {0};
    s.tstamp_mode = 1; s.period_step = 1; s.start_threshold = 1;
    s.avail_min = 1; s.stop_threshold = buf; s.xfer_align = 1;
    if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &s)!= 0) return -1;
    if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0)!= 0) return -1;
    ioctl(fd, SNDRV_PCM_IOCTL_START, 0);
    return 0;
}

static void mic_restart(int fd) {
    if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0) != 0) {
        log_err("transcriber: mic prepare failed\n");
    }
    if (ioctl(fd, SNDRV_PCM_IOCTL_START, 0) != 0) {

    }
}

static int mic_try_open(const char *path, int *out_channels) {
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    for (int ch = 2; ch >= 1; ch--) {
        if (alsa_hw_configure(fd, ch) == 0) { *out_channels = ch; return fd; }
        ioctl(fd, SNDRV_PCM_IOCTL_DROP, 0);
    }
    close(fd);
    return -1;
}

static int mic_scan_alsa(void) {
    DIR *d = opendir("/dev/snd");
    if (!d) return -1;

    char names[16][16];
    unsigned keys[16];
    int n = 0;
    struct dirent *ent;
    while (n < 16 && (ent = readdir(d))!= NULL) {
        if (strncmp(ent->d_name, "pcmC", 4)!= 0) continue;
        size_t l = strlen(ent->d_name);
        if (l < 8 || l >= 16 || ent->d_name[l-1]!= 'c') continue;
        unsigned card, dev; char tail;
        if (sscanf(ent->d_name, "pcmC%uD%u%c", &card, &dev, &tail)!= 3 || tail!= 'c') continue;
        strcpy(names[n], ent->d_name);
        keys[n] = card * 256 + dev;
        n++;
    }
    closedir(d);

    for (int i = 0; i < n; i++) for (int j = i+1; j < n; j++) if (keys[j] < keys[i]) {
        unsigned tk = keys[i]; keys[i] = keys[j]; keys[j] = tk;
        char t[16]; strcpy(t, names[i]); strcpy(names[i], names[j]); strcpy(names[j], t);
    }

    for (int i = 0; i < n; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/snd/%s", names[i]);
        int ch = 0;
        int fd = mic_try_open(path, &ch);
        if (fd >= 0) { g_resampler.channels = ch; return fd; }
    }
    return -1;
}

static int mic_open(void) {
    int fd = mic_scan_alsa();
    if (fd >= 0) return fd;
    fatal("no usable mic (ALSA only build; need audio group or busy device?)");
    return -1;
}

static int input_scan(int *fds, int cap) {
    int n = 0;
    for (int i = 0; i < 32 && n < cap; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        unsigned long bits[(KEY_MAX + 7) / 8 / sizeof(long)] = {0};
        if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(bits)), bits) < 0) { close(fd); continue; }
        unsigned long mask = 1UL << (KEY_CODE % (8 * sizeof(long)));
        if (!(bits[KEY_CODE / (8 * sizeof(long))] & mask)) { close(fd); continue; }
        fds[n++] = fd;
    }
    return n;
}

static void tls_init(const char *host) {
    br_x509_minimal_init(&g_tls.xc, &br_sha256_vtable, TAs, TAs_NUM);
    br_x509_minimal_set_hash(&g_tls.xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&g_tls.xc, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_rsa(&g_tls.xc, br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(&g_tls.xc, &br_ec_all_m31, br_ecdsa_i31_vrfy_asn1);
    br_ssl_client_zero(&g_tls.sc);

#ifdef BR_TLS13
    br_ssl_engine_set_versions(&g_tls.sc.eng, BR_TLS12, BR_TLS13);
#else
    br_ssl_engine_set_versions(&g_tls.sc.eng, BR_TLS12, 0x0304);
#endif
    br_ssl_engine_set_suites(&g_tls.sc.eng, TLS_SUITES, sizeof(TLS_SUITES)/sizeof(TLS_SUITES[0]));
    br_ssl_engine_set_hash(&g_tls.sc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(&g_tls.sc.eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_prf10(&g_tls.sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha256(&g_tls.sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&g_tls.sc.eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_default_aes_gcm(&g_tls.sc.eng);
    br_ssl_engine_set_ec(&g_tls.sc.eng, &br_ec_all_m31);
    br_ssl_engine_set_rsavrfy(&g_tls.sc.eng, br_rsa_i31_pkcs1_vrfy);
    br_ssl_engine_set_ecdsa(&g_tls.sc.eng, br_ecdsa_i31_vrfy_asn1);
    br_ssl_engine_set_x509(&g_tls.sc.eng, &g_tls.xc.vtable);
    br_ssl_engine_set_buffer(&g_tls.sc.eng, g_tls.iobuf, sizeof(g_tls.iobuf), 0);
    br_ssl_client_reset(&g_tls.sc, host, 0);
}

static int dns_resolve_host(const char *host) {
    struct addrinfo hint = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL, *p;
    int rc = getaddrinfo(host, "443", &hint, &res);
    if (rc != 0 || !res) {
        g_remote_count = 0;
        return -1;
    }
    int n = 0;
    for (p = res; p && n < MAX_REMOTES; p = p->ai_next) {
        if (p->ai_addrlen > sizeof(g_remotes[0])) continue;
        memcpy(&g_remotes[n], p->ai_addr, p->ai_addrlen);
        g_remote_lens[n] = p->ai_addrlen;
        n++;
    }
    freeaddrinfo(res);
    if (n == 0) {
        g_remote_count = 0;
        return -1;
    }
    g_remote_count = n;
    return 0;
}

static int dns_resolve_once(const char *host) {
    return dns_resolve_host(host);
}

static int json_extract_text(const char *js, size_t n, char *out, size_t cap) {
    size_t i = 0;
    while (i + 6 < n) {
        const void *f = memchr(js + i, '"', (n - 6) - i);
        if (!f) break;
        i = (const char *)f - js;
        if (memcmp(js + i, "\"text\"", 6)!= 0) { i++; continue; }
        size_t j = i + 6;
        while (j < n && (js[j]==' '||js[j]=='\t'||js[j]=='\r'||js[j]=='\n')) j++;
        if (j >= n || js[j]!= ':') { i++; continue; }
        j++;
        while (j < n && (js[j]==' '||js[j]=='\t')) j++;
        if (j >= n || js[j]!= '"') { i++; continue; }
        j++;
        size_t o = 0;
        while (j < n && o + 4 < cap) {
            char c = js[j++];
            if (c == '"') { out[o]=0; return (int)o; }
            if (c!= '\\') { out[o++] = c; continue; }
            if (j >= n) break;
            char e = js[j++];
            switch (e) {
                case '"': out[o++]='"'; break;
                case '\\': out[o++]='\\'; break;
                case '/': out[o++]='/'; break;
                case 'n': out[o++]='\n'; break;
                case 'r': out[o++]='\r'; break;
                case 't': out[o++]='\t'; break;
                case 'u': {
                    if (j+4>n) break;
                    unsigned v=0;
                    for (int k=0;k<4;k++){ char h=js[j++]; v<<=4; if(h>='0'&&h<='9') v|=h-'0'; else if(h>='a'&&h<='f') v|=h-'a'+10; else if(h>='A'&&h<='F') v|=h-'A'+10; }
                    if (v<0x80) out[o++]=(char)v;
                    else if (v<0x800){ out[o++]=0xC0|(v>>6); out[o++]=0x80|(v&0x3F); }
                    else { out[o++]=0xE0|(v>>12); out[o++]=0x80|((v>>6)&0x3F); out[o++]=0x80|(v&0x3F); }
                    break;
                }
                default: out[o++]=e; break;
            }
        }
        out[o]=0;
        return (int)o;
    }
    return -1;
}

static int fd_poll(int fd, short ev, int timeout_ms) {
    struct pollfd p = {fd, ev, 0};
    int r = poll(&p, 1, timeout_ms);
    if (r <= 0) return -1;
    if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return -1;
    return 0;
}

static int tls_pump_once(br_ssl_engine_context *eng, int fd, short ev, int64_t deadline) {
    size_t n = 0;
    unsigned char *buf;
    int64_t left = deadline - now_ms();
    if (left <= 0) return -1;
    if (ev == POLLOUT) {
        buf = br_ssl_engine_sendrec_buf(eng, &n);
        if (n == 0) return -1;
        if (fd_poll(fd, POLLOUT, (int)left)!= 0) return -1;
        ssize_t w = send(fd, buf, n, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        br_ssl_engine_sendrec_ack(eng, (size_t)w);
    } else {
        buf = br_ssl_engine_recvrec_buf(eng, &n);
        if (n == 0) return -1;
        if (fd_poll(fd, POLLIN, (int)left)!= 0) return -1;
        ssize_t r = recv(fd, buf, n, 0);
        if (r <= 0) return -1;
        br_ssl_engine_recvrec_ack(eng, (size_t)r);
    }
    return 0;
}

static int tls_do_handshake(br_ssl_engine_context *eng, int fd, int64_t deadline) {
    for (;;) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_CLOSED) return -1;
        if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) return 0;
        short ev = (st & BR_SSL_SENDREC)? POLLOUT : POLLIN;
        if (tls_pump_once(eng, fd, ev, deadline)!= 0) return -1;
    }
}

static int tls_send_all(br_ssl_engine_context *eng, int fd, const uint8_t *data, size_t len, int64_t deadline) {
    size_t off = 0;
    while (off < len) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_CLOSED) return -1;
        if (st & BR_SSL_SENDREC) {
            if (tls_pump_once(eng, fd, POLLOUT, deadline)!= 0) return -1;
            continue;
        }
        if (st & BR_SSL_SENDAPP) {
            size_t avail = 0;
            unsigned char *buf = br_ssl_engine_sendapp_buf(eng, &avail);
            if (avail == 0) return -1;
            size_t w = len - off < avail? len - off : avail;
            memcpy(buf, data + off, w);
            br_ssl_engine_sendapp_ack(eng, w);
            br_ssl_engine_flush(eng, 0);
            off += w;
            continue;
        }
        if (tls_pump_once(eng, fd, POLLIN, deadline)!= 0) return -1;
    }
    return 0;
}

static ssize_t tls_recv_all(br_ssl_engine_context *eng, int fd, char *out, size_t cap, int64_t deadline) {
    size_t off = 0;
    while (off + 1 < cap) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_RECVAPP) {
            size_t avail = 0;
            unsigned char *buf = br_ssl_engine_recvapp_buf(eng, &avail);
            if (avail == 0) break;
            size_t w = off + avail > cap - 1? cap - 1 - off : avail;
            memcpy(out + off, buf, w);
            off += w;
            br_ssl_engine_recvapp_ack(eng, avail);
            continue;
        }
        if (st & BR_SSL_CLOSED) break;
        short ev = (st & BR_SSL_SENDREC)? POLLOUT : POLLIN;
        if (tls_pump_once(eng, fd, ev, deadline)!= 0) break;
    }
    out[off] = 0;
    return (ssize_t)off;
}

static int build_multipart_header(void) {
    int n = snprintf(g_multipart_head, sizeof(g_multipart_head),
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n%s\r\n"
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n%s\r\n"
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\n"
        "Content-Type: audio/wav\r\n\r\n", g_cfg.model, g_cfg.lang);
    if (n <= 0 || (size_t)n >= sizeof(g_multipart_head)) return -1;
    g_multipart_head_len = (size_t)n;
    return 0;
}

static int hex_val(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

static ssize_t http_decode_chunked(char *body, size_t blen) {
    size_t src = 0, dst = 0;
    while (src < blen) {

        size_t line_start = src;
        while (src < blen && body[src] != '\n') src++;
        if (src >= blen) return -1;
        size_t line_end = src;
        if (line_end > line_start && body[line_end-1] == '\r') line_end--;

        size_t semi = line_start;
        while (semi < line_end && body[semi] != ';') semi++;
        size_t hex_end = (semi < line_end) ? semi : line_end;

        size_t chunk_size = 0;
        bool got = false;
        for (size_t i=line_start;i<hex_end;i++) {
            int v = hex_val(body[i]);
            if (v < 0) {
                if (body[i]==' '||body[i]=='\t') continue;
                return -1;
            }
            got = true;
            if (chunk_size > (SIZE_MAX>>4)) return -1;
            chunk_size = (chunk_size<<4) | (size_t)v;
        }
        if (!got) return -1;
        src++;
        if (chunk_size == 0) {

            break;
        }
        if (src + chunk_size > blen) return -1;
        if (dst + chunk_size > blen) return -1;
        memmove(body+dst, body+src, chunk_size);
        dst += chunk_size;
        src += chunk_size;

        if (src < blen && body[src] == '\r') src++;
        if (src < blen && body[src] == '\n') src++;
    }
    return (ssize_t)dst;
}

static int http_parse_status(const char *resp, size_t rlen) {
    if (rlen < 12) return -1;
    if (memcmp(resp, "HTTP/", 5) != 0) return -1;
    if (resp[8] != ' ') return -1;
    if (!isdigit((unsigned char)resp[9])||!isdigit((unsigned char)resp[10])||!isdigit((unsigned char)resp[11])) return -1;
    return (resp[9]-'0')*100 + (resp[10]-'0')*10 + (resp[11]-'0');
}

static bool header_contains(const char *hdrs, size_t hlen, const char *needle) {

    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return false;
    for (size_t i=0;i+ nlen <= hlen;i++) {
        size_t j=0;
        for (;j<nlen;j++) {
            char a = hdrs[i+j];
            char b = needle[j];
            if (tolower((unsigned char)a) != tolower((unsigned char)b)) break;
        }
        if (j==nlen) return true;
    }
    return false;
}

static struct { bool xclip,xdotool; } g_tools;
static void tools_init(void) {
    g_tools.xclip=executable_in_path("xclip"); g_tools.xdotool=executable_in_path("xdotool");
}
static void paste_text_at_cursor(const char *text) {
    if (!g_tools.xclip || !g_tools.xdotool) {
        log_err("transcriber: paste skipped (need xclip+xdotool)\n");
        return;
    }
    size_t tlen=strlen(text);
    pid_t p = fork();
    if (p != 0) { if (p > 0) { int st_; while (waitpid(p, &st_, 0) < 0 && errno == EINTR) {} } return; }
    if (fork()!=0) _exit(0);
    int clip[2];
    if (pipe(clip)!=0) _exit(0);
    pid_t cp=fork();
    if(cp==0){ dup2(clip[0],STDIN_FILENO); close(clip[0]); close(clip[1]); execlp("xclip","xclip","-selection","clipboard","-i",(char*)0); _exit(0); }
    close(clip[0]);
    write_all(clip[1],text,tlen);
    close(clip[1]);
    if(cp>0){ int st_; while(waitpid(cp,&st_,0)<0&&errno==EINTR){} }
    struct timespec ts={0,300*1000000L}; nanosleep(&ts,NULL);
    pid_t pp=fork();
    if(pp==0){ execlp("xdotool","xdotool","key","ctrl+v",(char*)0); _exit(0); }
    if(pp>0){ int st_; while(waitpid(pp,&st_,0)<0&&errno==EINTR){} }
    _exit(0);
}

static int http_transmit_once(int memfd, uint32_t wav_data_len) {
    if (g_remote_count <= 0) return -1;
    int remote_idx = 0;
    uint32_t wav_total = WAV_HDR_SIZE + wav_data_len;
    size_t body_len = g_multipart_head_len + wav_total + sizeof(MULTIPART_TAIL) - 1;

    char req[1024];
    int rl = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"
        "Content-Type: multipart/form-data; boundary=" BOUNDARY "\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
        g_cfg.epath, g_cfg.host, g_cfg.api_key, body_len);
    if (rl <= 0 || (size_t)rl >= sizeof(req)) { explicit_bzero(req,sizeof(req)); return -1; }

    int fd = socket(g_remotes[remote_idx].ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { explicit_bzero(req,sizeof(req)); return -1; }
    int one=1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int fl = fcntl(fd, F_GETFL,0);
    if (fl>=0) fcntl(fd,F_SETFL, fl|O_NONBLOCK);

    if (connect(fd, (struct sockaddr*)&g_remotes[remote_idx], g_remote_lens[remote_idx])!=0 && errno!=EINPROGRESS) {
        close(fd); explicit_bzero(req,sizeof(req)); return -1;
    }
    if (fd_poll(fd, POLLOUT, 10000)!=0) { close(fd); explicit_bzero(req,sizeof(req)); return -1; }
    int err=0; socklen_t el=sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el)!=0 || err) {
        close(fd); explicit_bzero(req,sizeof(req)); return -1;
    }
    if (fl>=0) fcntl(fd,F_SETFL, fl);

    tls_init(g_cfg.host);
    if (br_ssl_engine_current_state(&g_tls.sc.eng) & BR_SSL_CLOSED) { close(fd); explicit_bzero(req,sizeof(req)); return -1; }

    int64_t hs_dead = now_ms()+12000;
    if (tls_do_handshake(&g_tls.sc.eng, fd, hs_dead)!=0) {
        close(fd); explicit_bzero(req,sizeof(req)); return -1;
    }

    int64_t deadline = now_ms()+45000;
    if (tls_send_all(&g_tls.sc.eng, fd, (uint8_t*)req, (size_t)rl, deadline)!=0) goto io_fail;
    if (tls_send_all(&g_tls.sc.eng, fd, (uint8_t*)g_multipart_head, g_multipart_head_len, deadline)!=0) goto io_fail;
    if (lseek(memfd,0,SEEK_SET)<0) goto io_fail;

    uint8_t chunk[2048];
    uint32_t left=wav_total;
    while(left>0){
        size_t want = left>sizeof(chunk)?sizeof(chunk):left;
        ssize_t r=read(memfd,chunk,want);
        if(r<=0) goto io_fail;
        if(tls_send_all(&g_tls.sc.eng, fd, chunk, (size_t)r, deadline)!=0) goto io_fail;
        left-=(uint32_t)r;
    }
    if(tls_send_all(&g_tls.sc.eng, fd, (uint8_t*)MULTIPART_TAIL, sizeof(MULTIPART_TAIL)-1, deadline)!=0) goto io_fail;

    explicit_bzero(req,sizeof(req));
    ssize_t rlen = tls_recv_all(&g_tls.sc.eng, fd, g_tls.resp, sizeof(g_tls.resp), deadline);
    close(fd);
    if (rlen<=0) return -1;
    if (rlen >= (ssize_t)sizeof(g_tls.resp)-1) log_err("transcriber: HTTP response truncated at 8K\n");

    int code = http_parse_status(g_tls.resp, (size_t)rlen);
    if (code<0) return -1;

    const char *hdr_end = strstr(g_tls.resp, "\r\n\r\n");
    if (!hdr_end) return -1;
    size_t header_len = (size_t)(hdr_end - g_tls.resp) + 4;
    const char *body = hdr_end+4;
    size_t blen = (size_t)rlen - header_len;

    bool is_chunked = header_contains(g_tls.resp, header_len, "transfer-encoding: chunked");
    if (is_chunked) {
        ssize_t decoded = http_decode_chunked((char*)body, blen);
        if (decoded < 0) return -1;
        blen = (size_t)decoded;
    }

    if (code!=200) return code;

    int tlen = json_extract_text(body, blen, g_tls.transcript, sizeof(g_tls.transcript));
    if (tlen<0) return -1;

    size_t skip = strspn(g_tls.transcript, " \t\r\n");
    if (skip) memmove(g_tls.transcript, g_tls.transcript+skip, (size_t)tlen-skip+1);
    if (!g_tls.transcript[0]) return 0;
    paste_text_at_cursor(g_tls.transcript);
    return 0;

io_fail:
    close(fd);
    explicit_bzero(req,sizeof(req));
    return -1;
}

static int record_while_held(int *evfds, int nev, int pcm_fd, int64_t t0, uint32_t *out_data_len) {
    int mfd = memfd_create("trb", MFD_CLOEXEC);
    if (mfd < 0) {
        log_err("transcriber: memfd_create failed\n");
        return -1;
    }
    uint8_t hdr[WAV_HDR_SIZE];
    wav_fill_header(hdr,0);
    if (write_all(mfd,hdr,sizeof(hdr))<0){ log_err("transcriber: wav header write failed\n"); close(mfd); return -1; }

    uint32_t total=0;
    ioctl(pcm_fd,SNDRV_PCM_IOCTL_DROP,0);
    mic_restart(pcm_fd);
    g_resampler.acc=0; g_resampler.pending=0;

    struct pollfd pf[MAX_INPUT_DEVS];
    for(int i=0;i<nev;i++){ pf[i].fd=evfds[i]; pf[i].events=POLLIN; }

    int16_t pcm_tmp[PCM_FRAMES];

    int iter = 0;
    for(;;){
        int r=poll(pf,nev,20);
        if(r<0 && errno!=EINTR) { log_err("transcriber: poll in record failed\n"); break; }

        for(int i=0;i<nev;i++){
            if(pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)) { log_err("transcriber: input device error during record\n"); goto released; }
            if(!(pf[i].revents & POLLIN)) continue;
            struct input_event ev;
            while(read(evfds[i],&ev,sizeof(ev))==sizeof(ev)){
                if(ev.type!=EV_KEY || ev.code!=KEY_CODE) continue;
                if(ev.value==2) continue;
                if(ev.value==0) goto released;
            }
        }

        for(;;){
            ssize_t n=resample_read(pcm_fd,&g_resampler,pcm_tmp,PCM_FRAMES);
            if(n<0){
                if(errno==EAGAIN||errno==EWOULDBLOCK) break;
                if(errno==EPIPE){ log_err("transcriber: ALSA overrun, restarting mic\n"); mic_restart(pcm_fd); break; }
                if(errno==EINTR) continue;
                log_err("transcriber: mic read failed\n");
                break;
            }
            if(n==0) break;
            if(total+(uint32_t)n > MAX_WAV_DATA){
                log_err("transcriber: max duration reached, stopping\n");
                goto released;
            }
            if(write_all(mfd,pcm_tmp,(size_t)n)<0){ log_err("transcriber: memfd write failed\n"); close(mfd); return -1; }
            total+=(uint32_t)n;
        }

        if((++iter % 5)==0 && now_ms()-t0 > PRESS_MAX_MS){
            log_err("transcriber: press exceeded max 60s, discarding\n");
            close(mfd); return -1;
        }
    }

released:
    {
        int64_t dur = now_ms()-t0;
        if(dur < PRESS_MIN_MS){
            close(mfd); return -1;
        }
        if(total==0){
            log_err("transcriber: no audio captured, discarding\n");
            close(mfd); return -1;
        }
    }
    wav_fill_header(hdr,total);
    if(lseek(mfd,0,SEEK_SET)<0){ log_err("transcriber: lseek failed\n"); close(mfd); return -1; }
    if(write_all(mfd,hdr,sizeof(hdr))<0){ log_err("transcriber: wav header rewrite failed\n"); close(mfd); return -1; }
    *out_data_len=total;
    return mfd;
}

static void tls_state_clear(void) {
    size_t sz = sizeof(g_tls);

    size_t pagesz = 4096;
    size_t rounded = (sz + pagesz -1) & ~(pagesz-1);
    if(madvise(&g_tls, rounded, MADV_DONTNEED)!=0) explicit_bzero(&g_tls, sz);
}

int main(int argc, char **argv) {
    (void)argv;
    if(argc>1){ log_err("usage: transcriber (no flags; TRANSCRIBE_* env only)\n"); return 1; }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    disable_core_dumps();

    config_load();

    check_anchor_expiry();

    if(dns_resolve_once(g_cfg.host)!=0){
        log_err("transcriber: DNS resolve failed (phase 0): ");
        log_err(g_cfg.host);
        log_err("\n");
        secure_wipe_cfg();
        return 1;
    }
    if(build_multipart_header()!=0) { secure_wipe_cfg(); fatal("provider config too long"); }

    int pcm_fd = mic_open();

    int evfds[MAX_INPUT_DEVS];
    int nev = input_scan(evfds, MAX_INPUT_DEVS);
    if(nev==0){ secure_wipe_cfg(); fatal("no key-capable event device found (need input group?)"); }

    tools_init();
    if(!g_tools.xclip || !g_tools.xdotool)
        log_err("transcriber: no xclip/xdotool on PATH (paste will fail)\n");

    struct pollfd pf[MAX_INPUT_DEVS];
    for(int i=0;i<nev;i++){ pf[i].fd=evfds[i]; pf[i].events=POLLIN; }

    for(;;){
        if(poll(pf,nev,-1)<0){
            if(errno==EINTR) continue;
            log_err("transcriber: poll failed, retrying\n");
            struct timespec ts={1,0}; nanosleep(&ts,NULL);
            continue;
        }

        for(int i=0;i<nev;i++){
            if(pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)){
                log_err("transcriber: input device lost, rescanning\n");
                close(evfds[i]);
                for(int j=i;j+1<nev;j++){ evfds[j]=evfds[j+1]; pf[j]=pf[j+1]; }
                nev--; i--;
                continue;
            }
            if(!(pf[i].revents & POLLIN)) continue;

            struct input_event ev;
            while(read(evfds[i],&ev,sizeof(ev))==sizeof(ev)){
                if(ev.type!=EV_KEY || ev.code!=KEY_CODE || ev.value==2 || ev.value!=1) continue;
                int64_t t0=now_ms();
                uint32_t wlen=0;
                int mfd=record_while_held(evfds,nev,pcm_fd,t0,&wlen);
                if(mfd<0){
                    tls_state_clear();
                    continue;
                }

                int rc = http_transmit_once(mfd,wlen);
                if(rc>0){
                    log_err("transcriber: HTTP ");
                    char b[16]; int n=snprintf(b,sizeof(b),"%03d",rc);
                    if(n>0) write_all(STDERR_FILENO,b,strlen(b));
                    log_err("\n");
                } else if(rc!=0){
                    log_err("transcriber: send failed (no retry in slim build)\n");
                }
                close(mfd);
                tls_state_clear();
            }
        }

        if(nev==0){
            while((nev=input_scan(evfds,MAX_INPUT_DEVS))==0){
                struct timespec ts={1,0}; nanosleep(&ts,NULL);
            }
            log_err("transcriber: input recovered\n");
            for(int i=0;i<nev;i++){ pf[i].fd=evfds[i]; pf[i].events=POLLIN; }
        }
    }
}
