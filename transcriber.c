#define _GNU_SOURCE
/* transcriber: hold RightCtrl -> record 48k->16k mono -> Groq Whisper -> paste at cursor.
   Pipeline: evdev poll (idle, 0 wakeups) -> memfd WAV -> TLS1.2/BearSSL -> xclip/xdotool.
   Single file, no heap in hot path; g_sess is page-aligned and MADV_DONTNEEDed per press. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/input.h>
#include <sound/asound.h>
#include <bearssl.h>
#include "ta.h"

#define MAX_EVENTS 8
#define SAMPLE_RATE 16000
#define CHANNELS 1
#define PCM_SAMPLES 2048
#define PRESS_MIN_MS 300
#define PRESS_MAX_MS 60000
#define MAX_WAV_DATA (60u*16000u*2u)
#define WAV_HDR_LEN 44
#define RESP_MAX 8192
#define TEXT_MAX 4096
#define BOUNDARY "wzp0boundary7f3a1c9e"
#define HOST_MAX 128
#define MODEL_MAX 64
#define LANG_MAX 16
#define EPATH_MAX 192
#define APIKEY_MAX 512

static const int g_keycode = KEY_RIGHTCTRL;

static struct __attribute__((aligned(4096))) session {
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    unsigned char tlsbuf[BR_SSL_BUFSIZE_BIDI];
    char resp[RESP_MAX];
    char tout[TEXT_MAX];
    int16_t pcmbuf[PCM_SAMPLES];
} g_sess;
_Static_assert(sizeof g_sess % 4096 == 0, "page multiple");

static char g_apikey[APIKEY_MAX];
static char g_host[HOST_MAX] = "api.groq.com";
static char g_model[MODEL_MAX] = "whisper-large-v3-turbo";
static char g_lang[LANG_MAX] = "en";
static char g_epath[EPATH_MAX] = "/openai/v1/audio/transcriptions";

static struct sockaddr_storage g_dst;
static socklen_t g_dstlen;
static br_ssl_session_parameters g_tls_sess;
static unsigned g_tls_sess_valid;

// mic downsample state: 48k -> 16k (/3) + stereo->mono
static int g_mic_cfg = 2; // 2 stereo, 1 mono
static int16_t conv_raw[2048];
static int32_t conv_acc;
static int conv_n;

static char part1_head[512];
static size_t part1_len;
static const char part_tail[] = "\r\n--" BOUNDARY "--\r\n";

static const uint16_t tls_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};

/* utils */
static ssize_t write_all(int fd, const void *b, size_t n) {
    const unsigned char *p = b;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += w;
    }
    return off;
}
static void eput(const char *s) { write_all(2, s, strlen(s)); }
static void die(const char *m) { eput("transcriber: "); eput(m); eput("\n"); exit(1); }
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}
static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, 0);
}
static void wait_quiet(pid_t pid) {
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR);
}
static void poll_init(struct pollfd *pf, int *fds, int n) {
    for (int i = 0; i < n; i++) { pf[i].fd = fds[i]; pf[i].events = POLLIN; }
}
static int on_path(const char *name) {
    const char *pv = getenv("PATH");
    if (!pv || !*pv) pv = "/usr/bin:/bin";
    size_t nl = strlen(name);
    const char *s = pv;
    for (;;) {
        const char *e = strchr(s, ':');
        size_t dl = e? (size_t)(e - s) : strlen(s);
        if (dl && dl + nl + 2 <= 256) {
            char p[256];
            memcpy(p, s, dl); p[dl] = '/';
            memcpy(p + dl + 1, name, nl + 1);
            if (access(p, X_OK) == 0) return 1;
        }
        if (!e) break;
        s = e + 1;
    }
    return 0;
}
static void cfg_str(const char *name, char *dst, size_t cap) {
    const char *e = getenv(name);
    if (!e || !*e) return;
    size_t n = strlen(e);
    if (n >= cap) { eput("transcriber: "); eput(name); eput(" too long\n"); exit(1); }
    memcpy(dst, e, n + 1);
    explicit_bzero((char *)e, n);
    unsetenv(name);
}
static void key_init(void) {
    const char *e = getenv("TRANSCRIBE_API_KEY");
    if (!e || !*e) die("TRANSCRIBE_API_KEY not set in environment");
    size_t n = strlen(e);
    if (n >= APIKEY_MAX) die("TRANSCRIBE_API_KEY too long");
    memcpy(g_apikey, e, n + 1);
    explicit_bzero((char *)e, n);
    unsetenv("TRANSCRIBE_API_KEY");
    cfg_str("TRANSCRIBE_HOST", g_host, sizeof g_host);
    cfg_str("TRANSCRIBE_MODEL", g_model, sizeof g_model);
    cfg_str("TRANSCRIBE_LANGUAGE", g_lang, sizeof g_lang);
    cfg_str("TRANSCRIBE_PATH", g_epath, sizeof g_epath);
}

/* pcm conversion: 48k -> 16k (/3) + stereo->mono.
   Batch triples: 1 branch + 1 /3 per 3 frames instead of per-sample
   branch. Arithmetic order (truncation) identical to scalar version. */
static ssize_t conv_read(int pcm, int16_t *out, size_t cap) {
    ssize_t r;
    do { r = read(pcm, conv_raw, sizeof conv_raw); } while (r < 0 && errno == EINTR);
    if (r <= 0) return r;
    int32_t acc = conv_acc;
    int n = conv_n;
    size_t o = 0;
    if (g_mic_cfg == 1) {
        size_t ns = (size_t)r / 2, i = 0;
        // align to triple boundary (<=2 scalar steps, carries acc across reads)
        while (n && i < ns && o < cap) {
            acc += conv_raw[i++];
            if (++n == 3) { out[o++] = acc / 3; acc = 0; n = 0; }
        }
        // bulk: 3 samples -> 1 output, no per-sample branch
        while (i + 3 <= ns && o < cap) {
            int32_t s = (int32_t)conv_raw[i] + conv_raw[i+1] + conv_raw[i+2];
            out[o++] = s / 3;
            i += 3;
        }
        while (i < ns && o < cap) { acc += conv_raw[i++]; ++n; }
    } else {
        size_t nf = (size_t)r / 4, i = 0;
        int16_t *s = conv_raw;
        while (n && i < nf && o < cap) {
            acc += (s[2*i] + s[2*i+1]) / 2;
            i++;
            if (++n == 3) { out[o++] = acc / 3; acc = 0; n = 0; }
        }
        while (i + 3 <= nf && o < cap) {
            int32_t m0 = (s[2*i] + s[2*i+1]) / 2;
            int32_t m1 = (s[2*i+2] + s[2*i+3]) / 2;
            int32_t m2 = (s[2*i+4] + s[2*i+5]) / 2;
            out[o++] = (m0 + m1 + m2) / 3;
            i += 3;
        }
        while (i < nf && o < cap) { acc += (s[2*i] + s[2*i+1]) / 2; i++; ++n; }
    }
    conv_acc = acc;
    conv_n = n;
    return o * 2; // bytes
}

/* alsa */
static int alsa_setup(int fd, int want_ch) {
    struct snd_pcm_hw_params p = {0};
    for (int i = 0; i < 3; i++) for (int w = 0; w < 8; w++) p.masks[i].bits[w] = ~0u;
    for (int i = 0; i < 12; i++) { p.intervals[i].min = 0; p.intervals[i].max = ~0u; }
    p.masks[0].bits[0] = 1u << SNDRV_PCM_ACCESS_RW_INTERLEAVED;
    p.masks[1].bits[0] = 1u << SNDRV_PCM_FORMAT_S16_LE;
    p.masks[2].bits[0] = 1u << SNDRV_PCM_SUBFORMAT_STD;
    for (int w = 1; w < 8; w++) p.masks[0].bits[w] = p.masks[1].bits[w] = p.masks[2].bits[w] = 0;

    p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].max = 16;
    p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].max = 16 * want_ch;
    p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].min = p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].max = want_ch;
    p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].min = p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].max = 48000;
    for (int i = 0; i < 12; i++) p.intervals[i].integer = 1;
    p.intervals[SNDRV_PCM_HW_PARAM_TICK_TIME-8].integer = 0;
    p.rmask = (1u<<SNDRV_PCM_HW_PARAM_ACCESS)|(1u<<SNDRV_PCM_HW_PARAM_FORMAT)|(1u<<SNDRV_PCM_HW_PARAM_SUBFORMAT)
            |(1u<<SNDRV_PCM_HW_PARAM_SAMPLE_BITS)|(1u<<SNDRV_PCM_HW_PARAM_FRAME_BITS)
            |(1u<<SNDRV_PCM_HW_PARAM_CHANNELS)|(1u<<SNDRV_PCM_HW_PARAM_RATE);

    if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &p) != 0) return -1;
    unsigned buf = p.intervals[SNDRV_PCM_HW_PARAM_BUFFER_SIZE-8].max;
    if (buf < 16) buf = 16;

    struct snd_pcm_sw_params s = {0};
    s.tstamp_mode = 1; s.period_step = 1; s.start_threshold = 1;
    s.avail_min = 1; s.stop_threshold = buf; s.xfer_align = 1;
    if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &s) != 0) return -1;
    if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0) != 0) return -1;
    ioctl(fd, SNDRV_PCM_IOCTL_START, 0);
    return 0;
}
static void mic_start(int fd) {
    ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0);
    ioctl(fd, SNDRV_PCM_IOCTL_START, 0);
}
static int mic_try(const char *path) {
    int fd = open(path, O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0) return -1;
    for (int ch = 2; ch >= 1; ch--) {
        g_mic_cfg = ch;
        if (alsa_setup(fd, ch) == 0) return fd;
        ioctl(fd, SNDRV_PCM_IOCTL_DROP, 0);
    }
    close(fd);
    return -1;
}
static int pcm_nums(const char *s, unsigned *card, unsigned *dev) {
    char tail;
    if (sscanf(s, "pcmC%uD%u%c", card, dev, &tail) == 3 && tail == 'c') return 0;
    return -1;
}
static int mic_scan(void) {
    DIR *d = opendir("/dev/snd");
    if (!d) return -1;
    char names[16][16];
    unsigned keys[16];
    int n = 0;
    struct dirent *ent;
    while (n < 16 && (ent = readdir(d))) {
        if (strncmp(ent->d_name, "pcmC", 4)!= 0) continue;
        size_t l = strlen(ent->d_name);
        if (l < 8 || l >= 16) continue;
        if (ent->d_name[l-1]!= 'c') continue;
        unsigned c, dv;
        if (pcm_nums(ent->d_name, &c, &dv)!= 0) continue;
        strcpy(names[n], ent->d_name);
        keys[n] = c * 256 + dv;
        n++;
    }
    closedir(d);
    // selection sort by card/dev
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) if (keys[j] < keys[i]) {
        unsigned tk = keys[i]; keys[i] = keys[j]; keys[j] = tk;
        char t[16]; strcpy(t, names[i]); strcpy(names[i], names[j]); strcpy(names[j], t);
    }
    for (int i = 0; i < n; i++) {
        char path[64];
        snprintf(path, sizeof path, "/dev/snd/%s", names[i]);
        int fd = mic_try(path);
        if (fd >= 0) return fd;
    }
    return -1;
}
static int mic_spawn(char *const argv[], pid_t *pid) {
    int fds[2];
    if (pipe(fds)!= 0) return -1;
    pid_t p = fork();
    if (p < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (p == 0) {
        dup2(fds[1], 1);
        close(fds[0]); close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    int fl = fcntl(fds[0], F_GETFL, 0);
    if (fl >= 0) fcntl(fds[0], F_SETFL, fl | O_NONBLOCK);
    *pid = p;
    return fds[0];
}
static int mic_fallback_one(char *const argv[]) {
    pid_t pid = -1;
    int fd = mic_spawn(argv, &pid);
    if (fd < 0) return -1;
    sleep_ms(300);
    if (pid < 0 || kill(pid, 0) != 0) { close(fd); return -1; }
    return fd;
}
static int mic_fallback(void) {
    char *const a1[] = {"parec","--raw","--format=s16le","--rate=48000","--channels=1",0};
    char *const a2[] = {"arecord","-q","-D","default","-f","S16_LE","-r","48000","-c","1","-t","raw","-",0};
    char *const a3[] = {"pw-record","--format=s16","--rate=48000","--channels=1","-",0};
    int fd = -1;
    if (on_path("parec")) fd = mic_fallback_one(a1);
    if (fd < 0 && on_path("arecord")) fd = mic_fallback_one(a2);
    if (fd < 0 && on_path("pw-record")) fd = mic_fallback_one(a3);
    if (fd >= 0) {
        g_mic_cfg = 1;
        eput("transcriber: mic fallback 48k mono (sound server)\n");
    }
    return fd;
}
static int mic_open(void) {
    int fd = mic_scan();
    if (fd >= 0) {
        eput(g_mic_cfg == 2? "transcriber: mic 48k stereo -> 16k mono\n"
                            : "transcriber: mic 48k mono -> 16k mono\n");
        return fd;
    }
    fd = mic_fallback();
    if (fd >= 0) return fd;
    eput("transcriber: no usable mic (need audio group or busy device?)\n");
    exit(2);
}

/* input */
static int ev_autoscan(int *fds) {
    int n = 0;
    for (int i = 0; i < 32 && n < MAX_EVENTS; i++) {
        char path[64];
        snprintf(path, sizeof path, "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
        if (fd < 0) continue;
        unsigned long bits[(KEY_MAX+7)/8/sizeof(long)] = {0};
        if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof bits), bits) < 0) { close(fd); continue; }
        if (!(bits[g_keycode/(8*sizeof(long))] & (1UL << (g_keycode%(8*sizeof(long)))))) { close(fd); continue; }
        fds[n++] = fd;
    }
    return n;
}

/* wav */
static void wav_header(unsigned char *h, uint32_t data_len) {
    uint32_t riff = 36 + data_len, br = SAMPLE_RATE * CHANNELS * 2;
    uint32_t fmt_len = 16, sr = SAMPLE_RATE;
    uint16_t fmt = 1, ch = CHANNELS, bits = 16, ba = CHANNELS * 2;
    memcpy(h+0, "RIFF", 4); memcpy(h+4, &riff, 4); memcpy(h+8, "WAVEfmt ", 8);
    memcpy(h+16, &fmt_len, 4); memcpy(h+20, &fmt, 2); memcpy(h+22, &ch, 2);
    memcpy(h+24, &sr, 4); memcpy(h+28, &br, 4); memcpy(h+32, &ba, 2);
    memcpy(h+34, &bits, 2); memcpy(h+36, "data", 4); memcpy(h+40, &data_len, 4);
}

/* tls */
static void tls_profile_init(const char *host) {
    br_x509_minimal_init(&g_sess.xc, &br_sha256_vtable, TAs, TAs_NUM);
    br_x509_minimal_set_hash(&g_sess.xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&g_sess.xc, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_rsa(&g_sess.xc, br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(&g_sess.xc, &br_ec_all_m31, br_ecdsa_i31_vrfy_asn1);
    br_ssl_client_zero(&g_sess.sc);
    br_ssl_engine_set_versions(&g_sess.sc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&g_sess.sc.eng, tls_suites, sizeof tls_suites/sizeof tls_suites[0]);
    br_ssl_engine_set_hash(&g_sess.sc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(&g_sess.sc.eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_prf10(&g_sess.sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha256(&g_sess.sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&g_sess.sc.eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_default_aes_gcm(&g_sess.sc.eng);
    br_ssl_engine_set_ec(&g_sess.sc.eng, &br_ec_all_m31);
    br_ssl_engine_set_rsavrfy(&g_sess.sc.eng, br_rsa_i31_pkcs1_vrfy);
    br_ssl_engine_set_ecdsa(&g_sess.sc.eng, br_ecdsa_i31_vrfy_asn1);
    br_ssl_engine_set_x509(&g_sess.sc.eng, &g_sess.xc.vtable);
    br_ssl_engine_set_buffer(&g_sess.sc.eng, g_sess.tlsbuf, sizeof g_sess.tlsbuf, 1);
    if (g_tls_sess_valid) br_ssl_engine_set_session_parameters(&g_sess.sc.eng, &g_tls_sess);
    br_ssl_client_reset(&g_sess.sc, host, g_tls_sess_valid);
}
static int dns_resolve(const char *host, struct sockaddr_storage *dst, socklen_t *len) {
    struct addrinfo h = {.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM};
    struct addrinfo *r = 0;
    if (getaddrinfo(host, "443", &h, &r) != 0 || !r) return -1;
    memcpy(dst, r->ai_addr, r->ai_addrlen);
    *len = r->ai_addrlen;
    freeaddrinfo(r);
    return 0;
}
static int json_get_text(const char *js, size_t n, char *out, size_t cap) {
    // memchr fast-skip: only bytes equal to '"' can start "\"text\"",
    // so skipped bytes had no effect in the byte-wise scan. Parse of
    // each candidate below is verbatim the old logic.
    size_t i = 0;
    while (i + 6 < n) {
        const void *f = memchr(js + i, '"', (n - 6) - i);
        if (!f) break;
        i = (const char *)f - js;
        if (memcmp(js+i, "\"text\"", 6)!= 0) { i++; continue; }
        size_t j = i + 6;
        while (j < n && (js[j]==' '||js[j]=='\t'||js[j]=='\r'||js[j]=='\n')) j++;
        if (j >= n || js[j]!= ':') { i++; continue; } j++;
        while (j < n && (js[j]==' '||js[j]=='\t')) j++;
        if (j >= n || js[j]!= '"') { i++; continue; } j++;
        size_t o = 0;
        while (j < n && o + 4 < cap) {
            char c = js[j++];
            if (c == '"') { out[o]=0; return o; }
            if (c!= '\\') { out[o++]=c; continue; }
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
                if (v<0x80) out[o++]=v;
                else if (v<0x800){ out[o++]=0xC0|(v>>6); out[o++]=0x80|(v&0x3F); }
                else { out[o++]=0xE0|(v>>12); out[o++]=0x80|((v>>6)&0x3F); out[o++]=0x80|(v&0x3F); }
                break;
            }
            default: out[o++]=e; break;
            }
        }
        out[o]=0;
        return o;
    }
    return -1;
}

/* tls io */
static int tls_poll(int fd, short ev, int ms) {
    struct pollfd p = {fd, ev, 0};
    int r = poll(&p, 1, ms);
    if (r <= 0) return -1;
    if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return -1;
    return 0;
}
static int tls_pump(br_ssl_engine_context *eng, int fd, short ev, long long until) {
    size_t n=0; unsigned char *b;
    long long left = until - now_ms();
    if (left <= 0) return -1;
    if (ev == POLLOUT) {
        b = br_ssl_engine_sendrec_buf(eng, &n);
        if (!n) return -1;
        if (tls_poll(fd, POLLOUT, left)!= 0) return -1;
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        br_ssl_engine_sendrec_ack(eng, w);
    } else {
        b = br_ssl_engine_recvrec_buf(eng, &n);
        if (!n) return -1;
        if (tls_poll(fd, POLLIN, left)!= 0) return -1;
        ssize_t r = recv(fd, b, n, 0);
        if (r <= 0) return -1;
        br_ssl_engine_recvrec_ack(eng, r);
    }
    return 0;
}
static int tls_handshake(br_ssl_engine_context *eng, int fd, long long until) {
    for (;;) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_CLOSED) return -1;
        if (st & (BR_SSL_SENDAPP|BR_SSL_RECVAPP)) return 0;
        if (tls_pump(eng, fd, (st & BR_SSL_SENDREC)? POLLOUT : POLLIN, until)!= 0) return -1;
    }
}
static int tls_send_all(br_ssl_engine_context *eng, int fd, const unsigned char *p, size_t n, long long until) {
    size_t off=0;
    while (off < n) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_CLOSED) return -1;
        if (st & BR_SSL_SENDREC) { if (tls_pump(eng, fd, POLLOUT, until)!= 0) return -1; continue; }
        if (st & BR_SSL_SENDAPP) {
            size_t m=0; unsigned char *b = br_ssl_engine_sendapp_buf(eng, &m);
            if (!m) return -1;
            size_t w = n-off < m? n-off : m;
            memcpy(b, p+off, w);
            br_ssl_engine_sendapp_ack(eng, w);
            br_ssl_engine_flush(eng, 0);
            off+=w; continue;
        }
        if (tls_pump(eng, fd, POLLIN, until)!= 0) return -1;
    }
    return 0;
}
static ssize_t tls_read_all(br_ssl_engine_context *eng, int fd, char *out, size_t cap, long long until) {
    size_t off=0;
    while (off+1 < cap) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_RECVAPP) {
            size_t m=0; unsigned char *b = br_ssl_engine_recvapp_buf(eng, &m);
            if (!m) break;
            size_t w = off+m > cap-1? cap-1-off : m;
            memcpy(out+off, b, w); off+=w;
            br_ssl_engine_recvapp_ack(eng, m);
            continue;
        }
        if (st & BR_SSL_CLOSED) break;
        if (st & BR_SSL_SENDREC) { if (tls_pump(eng, fd, POLLOUT, until)!= 0) break; continue; }
        if (tls_pump(eng, fd, POLLIN, until)!= 0) break;
    }
    out[off]=0;
    return off;
}

/* http */
static int build_parts(void) {
    int n = snprintf(part1_head, sizeof part1_head,
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n%s\r\n"
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n%s\r\n"
        "--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\n"
        "Content-Type: audio/wav\r\n\r\n", g_model, g_lang);
    if (n <= 0 || (size_t)n >= sizeof part1_head) return -1;
    part1_len = n;
    return 0;
}
static void paste_at_cursor(const char *text);
static int transmit(int mfd, uint32_t wav_data_len) {
    uint32_t wav_total = WAV_HDR_LEN + wav_data_len;
    size_t body_len = part1_len + wav_total + sizeof part_tail - 1;

    char req[2048];
    int rl = snprintf(req, sizeof req,
        "POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"
        "Content-Type: multipart/form-data; boundary=" BOUNDARY "\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
        g_epath, g_host, g_apikey, body_len);
    if (rl <= 0 || (size_t)rl >= sizeof req) return -1;

    int fd = socket(g_dst.ss_family, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (fd < 0) goto fail_req;
    int one=1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl|O_NONBLOCK);
    if (connect(fd, (struct sockaddr*)&g_dst, g_dstlen)!= 0 && errno!= EINPROGRESS) goto fail;
    if (tls_poll(fd, POLLOUT, 10000)!= 0) goto fail;
    int err=0; socklen_t el=sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el)!= 0 || err) goto fail;
    fcntl(fd, F_SETFL, fl);

    tls_profile_init(g_host);
    if (br_ssl_engine_current_state(&g_sess.sc.eng) & BR_SSL_CLOSED) goto fail;
    long long until = now_ms() + 45000;
    if (tls_handshake(&g_sess.sc.eng, fd, now_ms()+12000)!= 0) { g_tls_sess_valid=0; goto fail; }
    br_ssl_engine_get_session_parameters(&g_sess.sc.eng, &g_tls_sess);
    g_tls_sess_valid = 1;

    if (tls_send_all(&g_sess.sc.eng, fd, (unsigned char*)req, rl, until)!= 0) goto fail;
    if (tls_send_all(&g_sess.sc.eng, fd, (unsigned char*)part1_head, part1_len, until)!= 0) goto fail;
    if (lseek(mfd, 0, SEEK_SET) < 0) goto fail;

    unsigned char chunk[16384];
    uint32_t left = wav_total;
    while (left) {
        size_t want = left > sizeof chunk? sizeof chunk : left;
        ssize_t r = read(mfd, chunk, want);
        if (r <= 0) goto fail;
        if (tls_send_all(&g_sess.sc.eng, fd, chunk, r, until)!= 0) goto fail;
        left -= r;
    }
    if (tls_send_all(&g_sess.sc.eng, fd, (unsigned char*)part_tail, sizeof part_tail-1, until)!= 0) goto fail;
    explicit_bzero(req, sizeof req);

    ssize_t rlen = tls_read_all(&g_sess.sc.eng, fd, g_sess.resp, sizeof g_sess.resp, until);
    close(fd);
    if (rlen <= 0) return -1;
    int code = 0;
    if (rlen > 12 && !memcmp(g_sess.resp, "HTTP/", 5) && g_sess.resp[8] == ' ')
        code = (g_sess.resp[9]-'0')*100 + (g_sess.resp[10]-'0')*10 + (g_sess.resp[11]-'0');
    if (code!= 200) return code;
    const char *body = strstr(g_sess.resp, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    size_t blen = rlen - (body - g_sess.resp);
    if (json_get_text(body, blen, g_sess.tout, sizeof g_sess.tout) < 0) return -1;
    paste_at_cursor(g_sess.tout);
    return 0;

fail:
    close(fd);
fail_req:
    explicit_bzero(req, sizeof req);
    return -1;
}

/* paste (X11 only, double-fork daemon) */
static void paste_at_cursor(const char *text) {
    const char *st = getenv("XDG_SESSION_TYPE");
    int wayland = (st && !strcmp(st, "wayland")) || (getenv("WAYLAND_DISPLAY") && !getenv("DISPLAY"));
    if (wayland || !on_path("xclip") || !on_path("xdotool")) {
        eput("transcriber: paste skipped (X11-only helpers)\n");
        return;
    }
    pid_t p = fork();
    if (p != 0) { if (p > 0) wait_quiet(p); return; }
    if (fork() != 0) _exit(0);

    int nullfd = open("/dev/null", O_WRONLY|O_CLOEXEC);
    if (nullfd >= 0) { dup2(nullfd, 1); if (nullfd != 1) close(nullfd); }

    int clip_pipe[2];
    if (pipe(clip_pipe) != 0) _exit(0);
    size_t tlen = strlen(text);
    pid_t clip_pid = fork();
    if (clip_pid == 0) {
        dup2(clip_pipe[0], 0); close(clip_pipe[0]); close(clip_pipe[1]);
        execlp("xclip","xclip","-selection","clipboard","-i",(char*)0);
        _exit(0);
    }
    close(clip_pipe[0]); write_all(clip_pipe[1], text, tlen); close(clip_pipe[1]);
    if (clip_pid > 0) wait_quiet(clip_pid);

    // wait for clipboard to contain our text
    long long deadline = now_ms() + 2000;
    size_t want = tlen;
    if (want > 255) want = 255;
    int ok = 0;
    char probe[256];
    while (!ok && now_ms() < deadline) {
        int out_pipe[2]; if (pipe(out_pipe) != 0) break;
        pid_t qpid = fork();
        if (qpid == 0) {
            dup2(out_pipe[1],1); close(out_pipe[0]); close(out_pipe[1]);
            execlp("xclip","xclip","-selection","clipboard","-o",(char*)0);
            _exit(0);
        }
        close(out_pipe[1]);
        ssize_t tot=0, r;
        while (tot < (ssize_t)want && (r=read(out_pipe[0], probe+tot, want-tot))>0) tot+=r;
        wait_quiet(qpid);
        close(out_pipe[0]);
        if (tot == (ssize_t)want && memcmp(probe, text, want)==0) ok=1;
        else sleep_ms(10);
    }
    if (!ok) _exit(0);

    pid_t paste_pid = fork();
    if (paste_pid == 0) { execlp("xdotool","xdotool","key","ctrl+shift+v",(char*)0); _exit(0); }
    if (paste_pid > 0) wait_quiet(paste_pid);
    _exit(0);
}

/* recording */
static int do_press(int *evfds, int nev, int pcm, long long t0, uint32_t *out_len) {
    int mfd = memfd_create("trb", MFD_CLOEXEC);
    if (mfd < 0) return -1;
    unsigned char hdr[WAV_HDR_LEN];
    wav_header(hdr, 0);
    if (write_all(mfd, hdr, sizeof hdr) < 0) { close(mfd); return -1; }

    uint32_t total = 0;
    ioctl(pcm, SNDRV_PCM_IOCTL_DROP, 0);
    mic_start(pcm);
    conv_acc = 0; conv_n = 0;

    struct pollfd pf[MAX_EVENTS];
    poll_init(pf, evfds, nev);

    for (;;) {
        int r = poll(pf, nev, 8);
        if (r < 0 && errno != EINTR) break;

        for (int i = 0; i < nev; i++) {
            if (pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)) goto released;
            if (!(pf[i].revents & POLLIN)) continue;
            struct input_event ev;
            while (read(evfds[i], &ev, sizeof ev) == sizeof ev) {
                if (ev.type != EV_KEY || ev.code != g_keycode) continue;
                if (ev.value == 2) continue;
                if (ev.value == 0) goto released;
            }
        }
        // drain pcm
        for (;;) {
            ssize_t n = conv_read(pcm, g_sess.pcmbuf, PCM_SAMPLES);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EPIPE) { mic_start(pcm); break; }
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            if (total + n > MAX_WAV_DATA) goto released;
            if (write_all(mfd, g_sess.pcmbuf, n) < 0) { close(mfd); return -1; }
            total += n;
        }
        if (now_ms() - t0 > PRESS_MAX_MS) { close(mfd); return -1; }
    }
released:
    if (now_ms() - t0 < PRESS_MIN_MS) { close(mfd); return -1; }
    wav_header(hdr, total);
    if (lseek(mfd, 0, SEEK_SET) < 0) { close(mfd); return -1; }
    if (write_all(mfd, hdr, sizeof hdr) < 0) { close(mfd); return -1; }
    *out_len = total;
    return mfd;
}
static void session_drop(void) {
    if (madvise(&g_sess, sizeof g_sess, MADV_DONTNEED)!= 0) explicit_bzero(&g_sess, sizeof g_sess);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) { eput("usage: transcriber (no flags; TRANSCRIBE_* env only)\n"); return 1; }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    key_init();

    int tries = 0;
    while (dns_resolve(g_host, &g_dst, &g_dstlen) != 0) {
        if (++tries >= 3) { eput("transcriber: DNS resolve failed (phase 0): "); eput(g_host); eput("\n"); return 1; }
        sleep_ms(2000);
    }
    eput("transcriber: dns ok\n");
    if (build_parts() != 0) die("provider config too long");

    int pcm = mic_open();
    int evfds[MAX_EVENTS];
    int nev = ev_autoscan(evfds);
    if (!nev) die("no key-capable event device found (need input group?)");
    eput("transcriber: ready\n");
    if (!on_path("xclip") || !on_path("xdotool")) eput("transcriber: no xclip/xdotool on PATH (paste will skip)\n");

    struct pollfd pf[MAX_EVENTS];
    poll_init(pf, evfds, nev);

    for (;;) {
        if (poll(pf, nev, -1) < 0) {
            if (errno == EINTR) continue;
            eput("transcriber: poll failed, retrying\n");
            sleep_ms(1000);
            continue;
        }
        for (int i = 0; i < nev; i++) {
            if (pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
                eput("transcriber: input device lost, rescanning\n");
                close(evfds[i]);
                for (int j = i; j + 1 < nev; j++) { evfds[j] = evfds[j+1]; pf[j] = pf[j+1]; }
                nev--; i--; continue;
            }
            if (!(pf[i].revents & POLLIN)) continue;
            struct input_event ev;
            while (read(evfds[i], &ev, sizeof ev) == sizeof ev) {
                if (ev.type != EV_KEY || ev.code != g_keycode || ev.value == 2 || ev.value != 1) continue;
                long long t = now_ms();
                uint32_t wlen = 0;
                int mfd = do_press(evfds, nev, pcm, t, &wlen);
                if (mfd < 0) { session_drop(); continue; }
                int rc = transmit(mfd, wlen);
                if (rc > 0) {
                    eput("transcriber: HTTP ");
                    char b[16]; snprintf(b, sizeof b, "%03d", rc); write_all(2, b, strlen(b)); eput("\n");
                } else if (rc != 0) eput("transcriber: send failed\n");
                close(mfd);
                session_drop();
            }
        }
        if (nev == 0) {
            while ((nev = ev_autoscan(evfds)) == 0) sleep_ms(1000);
            eput("transcriber: input recovered\n");
            poll_init(pf, evfds, nev);
        }
    }
}
