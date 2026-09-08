#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <dirent.h>	/* DT_* constants only; enum via getdents64(2), not opendir(3) */
#include <sys/syscall.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/input.h>
#include <sound/asound.h>
#include <bearssl.h>
#include "ta.h"		/* generated at build time by `brssl ta` from anchors/ */
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
#define EPATH_MAX 192	/* endpoint path; not the libc PATH_MAX */
#define APIKEY_MAX 512
static const char g_alsadev[] = "/dev/snd/pcmC0D0c";	/* preferred; mic_scan() tries the rest */
/* Right Ctrl is the only hotkey; no option exists to change it */
static const int g_keycode = KEY_RIGHTCTRL;
static struct __attribute__((aligned(4096))) session {
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	unsigned char tlsbuf[BR_SSL_BUFSIZE_BIDI];
	char resp[RESP_MAX];
	char tout[TEXT_MAX];
	int16_t pcmbuf[PCM_SAMPLES];
} g_sess;
/* MADV_DONTNEED rounds the length up to whole pages: g_sess must occupy an
 * exact page multiple or the wipe after each send would also zero the
 * globals that follow it in .bss (g_apikey etc.) */
_Static_assert(sizeof g_sess % 4096 == 0, "g_sess must be a page multiple");
static char g_apikey[APIKEY_MAX];
static size_t g_apikey_len;
/* TLS session-ID resumption (user-approved 2026-09-09): the master secret
 * (48 bytes) deliberately survives between sends so each dictation can do
 * an abbreviated handshake instead of a full ECDHE exchange (~1 RTT + key
 * agreement saved). It lives OUTSIDE g_sess so the page-wide wipe after
 * each send still covers the engine, transcript and buffers. Server may
 * refuse resumption: BearSSL then falls back to a full handshake silently.
 * Note TLS 1.2 resumption does not re-transmit the certificate: identity
 * is bound to the pinned-anchor-authenticated session that minted it. */
static br_ssl_session_parameters g_tls_sess;
static unsigned g_tls_sess_valid;
static char g_host[HOST_MAX] = "api.groq.com";
/* provider config (env-only, OpenAI-compatible /audio/transcriptions API):
 * TRANSCRIBE_HOST / _MODEL / _LANGUAGE / _PATH / _API_KEY. TLS still trusts
 * only anchors/ — a host whose chain doesn't terminate there fails closed. */
static char g_model[MODEL_MAX] = "whisper-large-v3-turbo";
static char g_lang[LANG_MAX] = "en";static char g_epath[EPATH_MAX] = "/openai/v1/audio/transcriptions";
static struct sockaddr_storage g_dst;
static socklen_t g_dstlen;
static ssize_t write_all(int fd, const void *b, size_t n);
static void paste_at_cursor(const char *text);
static void eput(const char *s) { write_all(2, s, strlen(s)); }
static void die(const char *m) {
	eput("transcriber: ");
	eput(m);
	eput("\n");
	exit(1);
}
static char *app_str(char *p, const char *s) {
	while (*s) *p++ = *s++;
	return p;
}
static char *app_u64(char *p, unsigned long long v) {
	char b[24], *q = b + sizeof b;
	*--q = 0;
	if (!v) *--q = '0';
	while (v) { *--q = (char)('0' + v % 10); v /= 10; }
	return app_str(p, q);
}
static long long now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}
static ssize_t write_all(int fd, const void *b, size_t n) {
	const unsigned char *p = b;
	size_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, p + off, n - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		off += (size_t)w;
	}
	return (ssize_t)off;
}
static void cfg_str(const char *name, char *dst, size_t cap) {
	const char *e = getenv(name);
	if (!e || !*e) return;
	size_t n = strlen(e);
	if (n >= cap) { /* fail fast at startup, not a mystery 404 later */
		eput("transcriber: "); eput(name); eput(" too long\n");
		exit(1);
	}
	memcpy(dst, e, n + 1);
	explicit_bzero((char *)e, n); /* same hygiene as the API key */
	unsetenv(name);
}
static void key_init(void) {
	const char *e = getenv("TRANSCRIBE_API_KEY");
	if (!e || !*e) die("TRANSCRIBE_API_KEY not set in environment");
	size_t n = strlen(e);
	if (n >= APIKEY_MAX) die("TRANSCRIBE_API_KEY too long");
	memcpy(g_apikey, e, n + 1);
	g_apikey_len = n;
	explicit_bzero((char *)e, n);
	unsetenv("TRANSCRIBE_API_KEY");
	cfg_str("TRANSCRIBE_HOST", g_host, sizeof g_host);
	cfg_str("TRANSCRIBE_MODEL", g_model, sizeof g_model);
	cfg_str("TRANSCRIBE_LANGUAGE", g_lang, sizeof g_lang);
	cfg_str("TRANSCRIBE_PATH", g_epath, sizeof g_epath);
}
static int pcm_tick_ms = 8;
static int mic_cfg = 2; /* capture channels opened: 2 = stereo, 1 = mono */
static int16_t conv_raw[2048];
static int32_t conv_acc;
static int conv_n;
static size_t conv_push(int32_t m, int16_t *out, size_t cap, size_t o) {
	conv_acc += m;
	if (++conv_n == 3) {
		if (o < cap) out[o++] = (int16_t)(conv_acc / 3);
		conv_acc = 0;
		conv_n = 0;
	}
	return o;
}
static ssize_t conv_read(int pcm, int16_t *out, size_t cap, int *more) {
	ssize_t r;
	do {
		r = read(pcm, conv_raw, sizeof conv_raw);
	} while (r < 0 && errno == EINTR);
	if (r <= 0) { *more = 0; return r; }
	*more = (r == (ssize_t)sizeof conv_raw);
	size_t o = 0;
	if (mic_cfg == 1) {
		size_t frames = (size_t)r / 2;
		for (size_t i = 0; i < frames; i++)
			o = conv_push(conv_raw[i], out, cap, o);
	} else {
		size_t frames = (size_t)r / 4;
		for (size_t i = 0; i < frames; i++)
			o = conv_push(((int32_t)conv_raw[2*i]+(int32_t)conv_raw[2*i+1])/2, out, cap, o);
	}
	return (ssize_t)(o * 2);
}
static int alsa_setup(int fd) {
	struct snd_pcm_hw_params p;
	memset(&p, 0, sizeof p);
	int want_ch = mic_cfg;
	for (int i = 0; i < 3; i++)
		for (int w = 0; w < 8; w++) p.masks[i].bits[w] = ~0u;
	for (int i = 0; i < 12; i++) {
		p.intervals[i].min = 0;
		p.intervals[i].max = ~0u;
	}
	p.masks[0].bits[0] = 1u << SNDRV_PCM_ACCESS_RW_INTERLEAVED;
	p.masks[1].bits[0] = 1u << SNDRV_PCM_FORMAT_S16_LE;
	p.masks[2].bits[0] = 1u << SNDRV_PCM_SUBFORMAT_STD;
	for (int w = 1; w < 8; w++)
		p.masks[0].bits[w] = p.masks[1].bits[w] = p.masks[2].bits[w] = 0;
	p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].min =
	p.intervals[SNDRV_PCM_HW_PARAM_SAMPLE_BITS-8].max = 16;
	p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].min =
	p.intervals[SNDRV_PCM_HW_PARAM_FRAME_BITS-8].max = 16*want_ch;
	p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].min =
	p.intervals[SNDRV_PCM_HW_PARAM_CHANNELS-8].max = want_ch;
	p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].min =
	p.intervals[SNDRV_PCM_HW_PARAM_RATE-8].max = 48000;
	for (int i = 0; i < 12; i++) p.intervals[i].integer = 1;
	p.intervals[SNDRV_PCM_HW_PARAM_TICK_TIME-8].integer = 0;
	p.rmask = (1u<<SNDRV_PCM_HW_PARAM_ACCESS)|(1u<<SNDRV_PCM_HW_PARAM_FORMAT)
		|(1u<<SNDRV_PCM_HW_PARAM_SUBFORMAT)|(1u<<SNDRV_PCM_HW_PARAM_SAMPLE_BITS)
		|(1u<<SNDRV_PCM_HW_PARAM_FRAME_BITS)|(1u<<SNDRV_PCM_HW_PARAM_CHANNELS)
		|(1u<<SNDRV_PCM_HW_PARAM_RATE);
	if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &p) != 0) return -1;
	unsigned buf = p.intervals[SNDRV_PCM_HW_PARAM_BUFFER_SIZE-8].max;
	if (buf < 16) buf = 16;
	pcm_tick_ms = 8;
	struct snd_pcm_sw_params s;
	memset(&s, 0, sizeof s);
	s.tstamp_mode = 1; s.period_step = 1; s.start_threshold = 1;
	s.avail_min = 1;
	s.stop_threshold = buf; s.xfer_align = 1;
	if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &s) != 0) return -1;
	if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE, 0) != 0) return -1;
	(void)ioctl(fd, SNDRV_PCM_IOCTL_START, 0);
	return 0;
}
static int mic_try(const char *path) {
	int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) return -1;
	for (int i = 0; i < 2; i++) { /* prefer stereo, fall back to mono */
		mic_cfg = i == 0 ? 2 : 1;
		if (alsa_setup(fd) == 0) return fd;
		(void)ioctl(fd, SNDRV_PCM_IOCTL_DROP, 0);
	}
	close(fd);
	return -1;
}
/* capture-PCM names under /dev/snd are pcmC<card>D<dev><c|p>; card/device
 * numbers are per-machine, so enumerate the directory instead of a
 * hard-coded grid */
static int mic_scan(void) {
	/* raw getdents64(2): opendir(3) mallocs a DIR — no heap, ever.
	 * kernel struct linux_dirent64: u64 ino, s64 off, u16 reclen,
	 * u8 type, char name[]; name NUL-terminated, padded to reclen. */
	int dfd = open("/dev/snd", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (dfd < 0) return -1;
	char buf[512];
	for (;;) {
		long r = syscall(SYS_getdents64, dfd, buf, sizeof buf);
		if (r <= 0) break;
		for (long o = 0; o < r; ) {
			unsigned rlen;
			memcpy(&rlen, buf + o + 16, 2); /* unaligned-safe */
			if (!rlen || o + rlen > r) break;
			unsigned type = (unsigned char)buf[o + 18];
			const char *nm = buf + o + 19;
			size_t nl = strnlen(nm, rlen - 19);
			if (nl < rlen - 19 && nl >= 8 && nl + 10 <= 64 &&
			    memcmp(nm, "pcm", 3) == 0 && nm[3] == 'C' &&
			    nm[nl-1] == 'c' && type != DT_DIR) {
				char p[64];
				memcpy(p, "/dev/snd/", 9);
				memcpy(p+9, nm, nl+1);
				int fd = mic_try(p);
				if (fd >= 0) { close(dfd); return fd; }
			}
			o += rlen;
		}
	}
	close(dfd);
	return -1;
}
static int mic_open(void) {
	int fd = mic_try(g_alsadev);
	if (fd < 0) fd = mic_scan();
	if (fd >= 0) {
		eput(mic_cfg == 2 ? "transcriber: mic 48k stereo -> 16k mono\n"
		                  : "transcriber: mic 48k mono -> 16k mono\n");
		return fd;
	}
	eput("transcriber: no usable mic (");
	eput(g_alsadev);
	eput(")\n");
	exit(2);
	return -1;
}
static int ev_autoscan(int *fds) {
	int n = 0;
	for (int i = 0; i < 32 && n < MAX_EVENTS; i++) {
		char path[64], *pe;
		pe = app_str(path, "/dev/input/event");
		pe = app_u64(pe, (unsigned)i);
		*pe = 0;
		int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) continue;
		/* KEY_MAX = 0x2ff: bitmap must cover the whole keycode space, not
		 * just 512 bits, or g_keycode indexing reads past the array */
		unsigned long bits[(KEY_MAX + 1 + 7) / 8 / sizeof(long)] = { 0 };
		if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof bits), bits) < 0) {
			close(fd);
			continue;
		}
		if (!(bits[g_keycode/(8*sizeof(long))]&(1UL<<(g_keycode%(8*sizeof(long)))))) {
			close(fd);
			continue;
		}
		/* no EVIOCGRAB: keep keyboard usable by X/apps */
		fds[n++] = fd;
	}
	return n;
}
static void wav_header(unsigned char *h, uint32_t data_len) {
	uint32_t riff = 36 + data_len, br = SAMPLE_RATE * CHANNELS * 2;
	uint32_t fmts = 16, sr = SAMPLE_RATE;
	uint16_t fmt = 1, ch = CHANNELS, bits = 16, ba = CHANNELS * 2;
	memcpy(h+0, "RIFF", 4); memcpy(h+4, &riff, 4); memcpy(h+8, "WAVEfmt ", 8);
	memcpy(h+16, &fmts, 4); memcpy(h+20, &fmt, 2); memcpy(h+22, &ch, 2);
	memcpy(h+24, &sr, 4); memcpy(h+28, &br, 4); memcpy(h+32, &ba, 2);
	memcpy(h+34, &bits, 2); memcpy(h+36, "data", 4); memcpy(h+40, &data_len, 4);
}
static const uint16_t tls_suites[] = { BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 };
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
	if (g_tls_sess_valid)
		br_ssl_engine_set_session_parameters(&g_sess.sc.eng, &g_tls_sess);
	br_ssl_client_reset(&g_sess.sc, host, g_tls_sess_valid);
}
static uint16_t rd16(const unsigned char *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static int dns_skip(const unsigned char *m, size_t n, int off) {
	int j = 0;
	while (off < (int)n) {
		unsigned c = m[off];
		if ((c&0xC0)==0xC0) { if (off+1 >= (int)n || ++j > 8) return -1; return off+2; }
		if (c == 0) return off+1;
		off += 1+c;
	}
	return -1;
}
/* all IPv4 nameservers from /etc/resolv.conf, in order; no hard-coded
 * fallback resolver (the old 127.0.0.53 default only works with
 * systemd-resolved's stub listener) */
static int dns_nameservers(struct sockaddr_in *out, int max) {
	int f = open("/etc/resolv.conf", O_RDONLY|O_CLOEXEC);
	if (f < 0) return 0;
	char rb[2048];
	ssize_t r = read(f, rb, sizeof rb-1);
	close(f);
	if (r <= 0) return 0;
	rb[r] = 0;
	int n = 0;
	for (char *ln = rb; ln && n < max; ) {
		char *eol = strchr(ln, '\n');
		if (eol) *eol = 0;
		while (*ln == ' ' || *ln == '\t') ln++;
		if (strncmp(ln, "nameserver", 10) == 0 && (ln[10] == ' ' || ln[10] == '\t')) {
			ln += 11;
			while (*ln == ' ' || *ln == '\t') ln++;
			char *e = ln;
			while (*e && *e != ' ' && *e != '\t') e++;
			char sv = *e;
			*e = 0;
			if (inet_pton(AF_INET, ln, &out[n].sin_addr) == 1) {
				out[n].sin_family = AF_INET;
				out[n].sin_port = htons(53);
				n++;
			}
			*e = sv;
		}
		ln = eol ? eol+1 : 0;
	}
	return n;
}
static int dns_resolve(const char *host, struct sockaddr_storage *dst, socklen_t *dstlen) {
	struct sockaddr_in ns4[4];
	int nns = dns_nameservers(ns4, 4);
	if (nns <= 0) return -1;
	unsigned char q[512], a[512];
	memset(q, 0, 12);
	uint16_t id = 0;
	getrandom(&id, sizeof id, 0);
	if (!id) id = 0x5eed;
	q[0] = (unsigned char)(id>>8); q[1] = (unsigned char)id;
	q[2] = 1;
	q[4] = 0; q[5] = 1;
	unsigned char *p = q+12;
	const char *s = host;
	for (;;) {
		const char *d = strchr(s, '.');
		size_t l = d ? (size_t)(d-s) : strlen(s);
		if (!l || l > 63 || (size_t)(p-q)+l+5 > sizeof q) return -1;
		*p++ = (unsigned char)l;
		memcpy(p, s, l);
		p += l;
		if (!d) break;
		s = d+1;
	}
	*p++ = 0; *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 1;
	size_t ql = (size_t)(p-q);
	int so = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
	if (so < 0) return -1;
	struct pollfd pf = { so, POLLOUT, 0 };
	for (int at = 0; at < 2; at++) {
	  for (int k = 0; k < nns; k++) {
		if (poll(&pf, 1, 2500) <= 0) continue;
		if (sendto(so, q, ql, 0, (struct sockaddr *)&ns4[k], sizeof ns4[k]) != (ssize_t)ql) continue;
		pf.events = POLLIN;
		if (poll(&pf, 1, 2500) <= 0) { pf.events = POLLOUT; continue; }
		ssize_t rl = recv(so, a, sizeof a, 0);
		pf.events = POLLOUT;
		if (rl < 12 || a[0] != q[0] || a[1] != q[1] || (a[3]&0x0F) || !(a[2]&0x80)) continue;
		int off = dns_skip(a, (size_t)rl, 12);
		if (off < 0 || off+4 > rl) continue;
		off += 4;
		unsigned an = rd16(a+6);
		for (unsigned i = 0; i < an && off+10 <= rl; i++) {
			int no = dns_skip(a, (size_t)rl, off);
			if (no < 0 || no+10 > rl) break;
			uint16_t t = rd16(a+no), dl = rd16(a+no+8);
			off = no+10;
			if (off+dl > rl) break;
			if (t == 1 && dl == 4) {
				struct sockaddr_in *v = (void *)dst;
				memset(v, 0, sizeof *v);
				v->sin_family = AF_INET;
				v->sin_port = htons(443);
				memcpy(&v->sin_addr, a+off, 4);
				*dstlen = sizeof *v;
				close(so);
				return 0;
			}
			off += dl;
		}
	  }
	}
	close(so);
	return -1;
}
static int json_get_text(const char *js, size_t n, char *out, size_t cap) {
	size_t o = 0;
	for (size_t i = 0; i + 6 < n; i++) {
		if (js[i] != '"') continue;
		if (memcmp(js+i, "\"text\"", 6) != 0) continue;
		size_t j = i + 6;
		while (j < n && (js[j]==' '||js[j]=='\t'||js[j]=='\r'||js[j]=='\n')) j++;
		if (j >= n || js[j] != ':') continue;
		j++;
		while (j < n && (js[j]==' '||js[j]=='\t')) j++;
		if (j >= n || js[j] != '"') continue;
		j++;
		while (j < n && o + 4 < cap) {
			char c = js[j++];
			if (c == '"') { out[o] = 0; return (int)o; }
			if (c != '\\') { out[o++] = c; continue; }
			if (j >= n) break;
			char e = js[j++];
			switch (e) {
			case '"': out[o++] = '"'; break;
			case '\\': out[o++] = '\\'; break;
			case '/': out[o++] = '/'; break;
			case 'n': out[o++] = '\n'; break;
			case 'r': out[o++] = '\r'; break;
			case 't': out[o++] = '\t'; break;
			case 'u': {
				if (j + 4 > n) break;
				unsigned v = 0;
				for (int k = 0; k < 4; k++) {
					char h = js[j++];
					v <<= 4;
					if (h >= '0' && h <= '9') v |= (unsigned)(h-'0');
					else if (h >= 'a' && h <= 'f') v |= (unsigned)(h-'a'+10);
					else if (h >= 'A' && h <= 'F') v |= (unsigned)(h-'A'+10);
				}
				if (v < 0x80) out[o++] = (char)v;
				else if (v < 0x800) {
					out[o++] = (char)(0xC0|(v>>6));
					out[o++] = (char)(0x80|(v&0x3F));
				} else {
					out[o++] = (char)(0xE0|(v>>12));
					out[o++] = (char)(0x80|((v>>6)&0x3F));
					out[o++] = (char)(0x80|(v&0x3F));
				}
				break;
			}
			default: out[o++] = e; break;
			}
		}
		out[o] = 0;
		return (int)o;
	}
	return -1;
}
static int tls_poll(int fd, short ev, int timeout_ms) {
	struct pollfd p = { fd, ev, 0 };
	int r = poll(&p, 1, timeout_ms);
	if (r <= 0) return -1;
	if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return -1;
	return 0;
}
static int tls_pump(br_ssl_engine_context *eng, int fd, short ev, long long until) {
	size_t n = 0;
	unsigned char *b;
	long long left = until - now_ms();
	if (left <= 0) return -1;
	if (ev == POLLOUT) {
		b = br_ssl_engine_sendrec_buf(eng, &n);
		if (n == 0) return -1;
		if (tls_poll(fd, POLLOUT, (int)left) != 0) return -1;
		ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
		if (w <= 0) return -1;
		br_ssl_engine_sendrec_ack(eng, (size_t)w);
	} else {
		b = br_ssl_engine_recvrec_buf(eng, &n);
		if (n == 0) return -1;
		if (tls_poll(fd, POLLIN, (int)left) != 0) return -1;
		ssize_t r = recv(fd, b, n, 0);
		if (r <= 0) return -1;
		br_ssl_engine_recvrec_ack(eng, (size_t)r);
	}
	return 0;
}
static int tls_handshake(br_ssl_engine_context *eng, int fd, long long until) {
	for (;;) {
		unsigned st = br_ssl_engine_current_state(eng);
		if (st & BR_SSL_CLOSED) return -1;
		if (st & (BR_SSL_SENDAPP|BR_SSL_RECVAPP)) return 0;
		if (tls_pump(eng, fd, (st & BR_SSL_SENDREC) ? POLLOUT : POLLIN, until) != 0)
			return -1;
	}
}
static int tls_send_all(br_ssl_engine_context *eng, int fd, const unsigned char *p, size_t n, long long until) {
	size_t off = 0;
	while (off < n) {
		unsigned st = br_ssl_engine_current_state(eng);
		if (st & BR_SSL_CLOSED) return -1;
		if (st & BR_SSL_SENDREC) {
			if (tls_pump(eng, fd, POLLOUT, until) != 0) return -1;
			continue;
		}
		if (st & BR_SSL_SENDAPP) {
			size_t m = 0;
			unsigned char *b = br_ssl_engine_sendapp_buf(eng, &m);
			if (m == 0) return -1;
			size_t w = n - off < m ? n - off : m;
			memcpy(b, p + off, w);
			br_ssl_engine_sendapp_ack(eng, w);
			br_ssl_engine_flush(eng, 0);
			off += w;
			continue;
		}
		if (tls_pump(eng, fd, POLLIN, until) != 0) return -1;
	}
	return 0;
}
static ssize_t tls_read_all(br_ssl_engine_context *eng, int fd, char *out, size_t cap, long long until) {
	size_t off = 0;
	while (off + 1 < cap) {
		unsigned st = br_ssl_engine_current_state(eng);
		if (st & BR_SSL_RECVAPP) {
			size_t m = 0;
			unsigned char *b = br_ssl_engine_recvapp_buf(eng, &m);
			if (m == 0) break;
			size_t w = off + m > cap - 1 ? cap - 1 - off : m;
			memcpy(out + off, b, w);
			off += w;
			br_ssl_engine_recvapp_ack(eng, m);
			continue;
		}
		if (st & BR_SSL_CLOSED) break;
		if (st & BR_SSL_SENDREC) {
			if (tls_pump(eng, fd, POLLOUT, until) != 0) break;
			continue;
		}
		if (tls_pump(eng, fd, POLLIN, until) != 0) break;
	}
	out[off] = 0;
	return (ssize_t)off;
}
static const char part_tail[] = "\r\n--" BOUNDARY "--\r\n";
static char part1_head[512];
static size_t part1_len;
static int tx_build_parts(void) {
	char *p = part1_head;
	char *end = part1_head + sizeof part1_head;
	char *put = p;
	#define PSTR(s) do { size_t L = sizeof(s)-1; if (put + L > end) return -1; \
		memcpy(put, s, L); put += L; } while (0)
	#define PBUF(b) do { size_t L = strlen(b); if (put + L > end) return -1; \
		memcpy(put, b, L); put += L; } while (0)
	PSTR("--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n");
	PBUF(g_model);
	PSTR("\r\n--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n");
	PBUF(g_lang);
	PSTR("\r\n--" BOUNDARY "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\nContent-Type: audio/wav\r\n\r\n");
	#undef PSTR
	#undef PBUF
	part1_len = (size_t)(put - p);
	return 0;
}
static int transmit(int mfd, uint32_t wav_data_len) {
	uint32_t wav_total = WAV_HDR_LEN + wav_data_len;
	unsigned long long body_len = (unsigned long long)part1_len+wav_total+(sizeof part_tail-1);
	/* bounded appends: req holds the API key, so it must never overflow
	 * and is wiped the moment it has been handed to TLS */
	#define APP(s) do { size_t L = sizeof(s)-1; if (rp + L > rend) goto fail; \
		memcpy(rp, s, L); rp += L; } while (0)
	#define APPV(s) do { size_t L = strlen(s); if (rp + L > rend) goto fail; \
		memcpy(rp, s, L); rp += L; } while (0)
	char req[2048], *rp = req, *rend = req + sizeof req;
	int fd = -1;	/* every failure funnels to fail:, which closes and wipes */
	APP("POST ");
	APPV(g_epath);
	APP(" HTTP/1.1\r\nHost: ");
	APPV(g_host);
	APP("\r\nAuthorization: Bearer ");
	APPV(g_apikey);	/* NUL-terminated, startup-length-capped */
	APP("\r\nContent-Type: multipart/form-data; boundary=" BOUNDARY "\r\nContent-Length: ");
	{
		char kb[24], *kp = kb + sizeof kb;
		*--kp = 0;
		if (!body_len) *--kp = '0';
		while (body_len) { *--kp = (char)('0' + body_len % 10); body_len /= 10; }
		APPV(kp);
	}
	APP("\r\nConnection: close\r\n\r\n");
	#undef APP
	#undef APPV
	size_t rl = (size_t)(rp - req);
	fd = socket(g_dst.ss_family, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (fd < 0) goto fail;
	{	/* send each finished TLS record at once; Nagle would park the
	 * tail segment until an RTT-elapsed ACK — free latency for us */
		int one = 1;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	}
	int fl = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, fl|O_NONBLOCK);
	if (connect(fd, (struct sockaddr *)&g_dst, g_dstlen) != 0 && errno != EINPROGRESS)
		goto fail;
	if (tls_poll(fd, POLLOUT, 10000) != 0) goto fail;
	int err = 0;
	socklen_t el = sizeof err;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err)
		goto fail;
	fcntl(fd, F_SETFL, fl);
	tls_profile_init(g_host);
	if (br_ssl_engine_current_state(&g_sess.sc.eng) & BR_SSL_CLOSED)
		goto fail;
	long long until = now_ms() + 45000;
	if (tls_handshake(&g_sess.sc.eng, fd, now_ms()+12000) != 0) {
		g_tls_sess_valid = 0;	/* poison guard: never reuse a dead session */
		goto fail;
	}
	br_ssl_engine_get_session_parameters(&g_sess.sc.eng, &g_tls_sess);
	g_tls_sess_valid = 1;
	if (tls_send_all(&g_sess.sc.eng, fd, (unsigned char *)req, rl, until) != 0 ||
	    tls_send_all(&g_sess.sc.eng, fd, (unsigned char *)part1_head, part1_len, until) != 0)
		goto fail;
	if (lseek(mfd, 0, SEEK_SET) < 0) goto fail;
	unsigned char chunk[4096];
	uint32_t left = wav_total;
	while (left) {
		size_t want = left > sizeof chunk ? sizeof chunk : left;
		ssize_t r = read(mfd, chunk, want);
		if (r <= 0) goto fail;
		if (tls_send_all(&g_sess.sc.eng, fd, chunk, (size_t)r, until) != 0)
			goto fail;
		left -= (uint32_t)r;
	}
	if (tls_send_all(&g_sess.sc.eng, fd, (unsigned char *)part_tail, sizeof part_tail-1, until) != 0)
		goto fail;
	explicit_bzero(req, sizeof req);	/* key handled: no residue */
	ssize_t rl2 = tls_read_all(&g_sess.sc.eng, fd, g_sess.resp, sizeof g_sess.resp, until);
	close(fd);
	fd = -1;
	if (rl2 <= 0) goto fail;
	int code = 0;
	{
		const char *s = g_sess.resp;
		if (s[0]=='H'&&s[1]=='T'&&s[2]=='T'&&s[3]=='P'&&s[4]=='/'&&s[6]=='.'&&s[8]==' '&&
		    s[9]>='0'&&s[9]<='9'&&s[10]>='0'&&s[10]<='9'&&s[11]>='0'&&s[11]<='9')
			code = (s[9]-'0')*100+(s[10]-'0')*10+(s[11]-'0');
	}
	if (code != 200)
		return code;	/* main logs one short line; positive = server reply */
	const char *body = strstr(g_sess.resp, "\r\n\r\n");
	if (!body) goto fail;
	body += 4;
	size_t blen = (size_t)rl2 - (size_t)(body - g_sess.resp);
	if (json_get_text(body, blen, g_sess.tout, sizeof g_sess.tout) < 0) goto fail;
	size_t tl = strlen(g_sess.tout);
	if (write_all(1, g_sess.tout, tl) < 0) return -1;
	if (tl == 0 || g_sess.tout[tl-1] != '\n')
		if (write_all(1, "\n", 1) < 0) return -1;
	paste_at_cursor(g_sess.tout);
	return 0;
fail:
	if (fd >= 0) close(fd);
	explicit_bzero(req, sizeof req);	/* carry no key residue out of a failed send */
	return -1;
}
static int on_path(const char *name) {
	const char *pv = getenv("PATH");
	if (!pv || !*pv) pv = "/usr/bin:/bin";
	size_t nl = strlen(name);
	const char *s = pv;
	for (;;) {
		const char *e = strchr(s, ':');
		size_t dl = e ? (size_t)(e-s) : strlen(s);
		if (dl && dl + nl + 2 <= 256) {
			char p[256];
			memcpy(p, s, dl); p[dl] = '/';
			memcpy(p+dl+1, name, nl+1);
			if (access(p, X_OK) == 0) return 1;
		}
		if (!e) break;
		s = e+1;
	}
	return 0;
}
static void paste_at_cursor(const char *text) {
	/* xclip/xdotool are X11-only; skip paste under Wayland or when the
	 * helpers are not on PATH, instead of silently typing nothing.
	 * XWayland sessions export DISPLAY too, so WAYLAND_DISPLAY alone is
	 * not proof of Wayland: XDG_SESSION_TYPE is the primary signal. */
	const char *st = getenv("XDG_SESSION_TYPE");
	int wl = (st && !strcmp(st, "wayland")) ||
	         (getenv("WAYLAND_DISPLAY") && !getenv("DISPLAY"));
	if (!on_path("xclip") || !on_path("xdotool") || wl) {
		eput("transcriber: paste skipped (X11-only helpers)\n");
		return;
	}
	pid_t p = fork();
	if (p != 0) {
		if (p > 0) {
			int s;
			while (waitpid(p, &s, 0) < 0 && errno == EINTR) ;
		}
		return;
	}
	if (fork() != 0) _exit(0);
	{
		int fds[2];
		if (pipe(fds) != 0) _exit(0);
		pid_t x = fork();
		if (x == 0) {
			dup2(fds[0], 0);
			close(fds[0]);
			close(fds[1]);
			execlp("xclip", "xclip", "-selection", "clipboard", "-i", (char *)0);
			_exit(0);
		}
		close(fds[0]);
		write_all(fds[1], text, strlen(text));
		close(fds[1]);
		if (x > 0) {
			int s;
			while (waitpid(x, &s, 0) < 0 && errno == EINTR) ;
		}
		/* paste only once the clipboard really holds the transcript:
		 * the old fixed 50 ms sleep raced xclip's ownership transfer
		 * and could paste stale clipboard content into the wrong window.
		 * xclip -o round-trip = the selection is actually served.
		 * probe immediately, then 10 ms steps up to a 2 s cap: the
		 * common case costs one xclip exec, not a fixed sleep */
		{
			char probe[256];
			size_t want = strlen(text);
			if (want > sizeof probe - 1) want = sizeof probe - 1;
			int ok = 0;
			long long deadline = now_ms() + 2000;
			for (;;) {
				int qfds[2];
				if (pipe(qfds) != 0) break;
				pid_t q = fork();
				if (q == 0) {
					dup2(qfds[1], 1);
					close(qfds[0]);
					close(qfds[1]);
					execlp("xclip", "xclip", "-selection", "clipboard", "-o", (char *)0);
					_exit(0);
				}
				close(qfds[1]);
				ssize_t r, tot = 0;
				while (tot < (ssize_t)want &&
				       (r = read(qfds[0], probe + tot, (size_t)(want - tot))) > 0)
					tot += r;
				int ws;
				while (waitpid(q, &ws, 0) < 0 && errno == EINTR) ;
				close(qfds[0]);
				if (tot == (ssize_t)want && memcmp(probe, text, want) == 0) {
					ok = 1;
					break;
				}
				if (now_ms() >= deadline) break;
				struct timespec ts = { 0, 10000000 };
				nanosleep(&ts, 0);
			}
			if (!ok) _exit(0);	/* never confirmed: paste nothing */
		}
		pid_t d = fork();
		if (d == 0) {
			execlp("xdotool", "xdotool", "key", "ctrl+shift+v", (char *)0);
			_exit(0);
		}
		if (d > 0) {
			int s;
			while (waitpid(d, &s, 0) < 0 && errno == EINTR) ;
		}
		_exit(0);
	}
}
static int do_press(int *evfds, int nev, int pcm, long long t0, uint32_t *out_len) {
	int mfd = memfd_create("trb", MFD_CLOEXEC);
	if (mfd < 0) return -1;
	unsigned char wh[WAV_HDR_LEN];
	wav_header(wh, 0);
	if (write_all(mfd, wh, sizeof wh) < 0) { close(mfd); return -1; }
	uint32_t total = 0;
	(void)ioctl(pcm, SNDRV_PCM_IOCTL_DROP, 0);
	(void)ioctl(pcm, SNDRV_PCM_IOCTL_PREPARE, 0);
	(void)ioctl(pcm, SNDRV_PCM_IOCTL_START, 0);
	conv_acc = 0; conv_n = 0;
	struct pollfd pf[MAX_EVENTS];
	for (int i = 0; i < nev; i++) {
		pf[i].fd = evfds[i];
		pf[i].events = POLLIN;
	}
	for (;;) {
		int r = poll(pf, (nfds_t)nev, pcm_tick_ms);
		if (r < 0 && errno != EINTR) break;
		for (int i = 0; i < nev; i++) {
			if (pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)) goto released;
			if (!(pf[i].revents & POLLIN)) continue;
		}
		for (int i = 0; i < nev; i++) {
			if (!(pf[i].revents & POLLIN)) continue;
			struct input_event ev;
			ssize_t n;
			while ((n = read(evfds[i], &ev, sizeof ev)) == sizeof ev) {
				if (ev.type != EV_KEY || ev.code != g_keycode) continue;
				if (ev.value == 2) continue;
				if (ev.value == 0) goto released;
			}
		}
		for (;;) {
			ssize_t n;
			int more = 0;
			n = conv_read(pcm, g_sess.pcmbuf, PCM_SAMPLES, &more);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) break;
				if (errno == EPIPE) {
					(void)ioctl(pcm, SNDRV_PCM_IOCTL_PREPARE, 0);
					(void)ioctl(pcm, SNDRV_PCM_IOCTL_START, 0);
					break;
				}
				if (errno == EINTR) continue;
				break;
			}
			if (n == 0) break;
			if (total + (uint32_t)n > MAX_WAV_DATA) break;
			if (write_all(mfd, g_sess.pcmbuf, (size_t)n) < 0) {
				close(mfd);
				return -1;
			}
			total += (uint32_t)n;
			if (!more && (uint32_t)n < sizeof g_sess.pcmbuf) break;
		}
		if (now_ms() - t0 > PRESS_MAX_MS) {
			close(mfd);
			return -1;
		}
	}
released: ;
	long long dur = now_ms() - t0;
	if (dur < PRESS_MIN_MS) { close(mfd); return -1; }
	wav_header(wh, total);
	if (lseek(mfd, 0, SEEK_SET) < 0) { close(mfd); return -1; }
	if (write_all(mfd, wh, sizeof wh) < 0) { close(mfd); return -1; }
	*out_len = total;
	return mfd;
}
static void session_drop(void) {
	if (madvise(&g_sess, sizeof g_sess, MADV_DONTNEED) != 0)
		explicit_bzero(&g_sess, sizeof g_sess);
}
static void usage(void) {
	eput("usage: transcriber (no flags; TRANSCRIBE_* env only)\n");
}
int main(int argc, char **argv) {
	(void)argv;
	if (argc > 1) {	/* no flags exist; fail fast on stray arguments */
		usage();
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	key_init();
	if (dns_resolve(g_host, &g_dst, &g_dstlen) != 0) { eput("transcriber: DNS resolve failed (phase 0): "); eput(g_host); eput("\n"); return 1; }
	eput("transcriber: dns ok\n");
	if (tx_build_parts() != 0) die("provider config too long");
	int pcm = mic_open();
	int evfds[MAX_EVENTS];
	int nev = ev_autoscan(evfds);
	if (!nev) die("no key-capable event device found");
	eput("transcriber: ready\n");
	struct pollfd pf[MAX_EVENTS];
	for (int i = 0; i < nev; i++) {
		pf[i].fd = evfds[i];
		pf[i].events = POLLIN;
	}
	for (;;) {
		if (poll(pf, (nfds_t)nev, -1) < 0) {
			if (errno == EINTR) continue;
			/* runtime failure: never exit — report, wait, retry */
			eput("transcriber: poll failed, retrying\n");
			struct timespec ts = { 1, 0 };
			nanosleep(&ts, 0);
			continue;
		}
		for (int i = 0; i < nev; i++) {
			if (pf[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				/* device vanished: drop it, rescan; never exit */
				eput("transcriber: input device lost, rescanning\n");
				close(evfds[i]);
				for (int j = i; j + 1 < nev; j++) {
					evfds[j] = evfds[j+1];
					pf[j] = pf[j+1];
				}
				nev--;
				i--;
				continue;
			}
			if (!(pf[i].revents & POLLIN)) continue;
			struct input_event ev;
			ssize_t r;
			while ((r = read(evfds[i], &ev, sizeof ev)) == sizeof ev) {
				if (ev.type != EV_KEY || ev.code != g_keycode) continue;
				if (ev.value == 2) continue;
				if (ev.value != 1) continue;
				long long t = now_ms();
				uint32_t wlen = 0;
				int mfd = do_press(evfds, nev, pcm, t, &wlen);
				if (mfd < 0) { session_drop(); continue; }
				{	/* one short line per failure, nothing on success */
					int r = transmit(mfd, wlen);
					if (r > 0) {	/* server said no: r = HTTP status */
						eput("transcriber: HTTP ");
						{
							char b[3];
							b[0] = (char)('0' + r / 100);
							b[1] = (char)('0' + (r / 10) % 10);
							b[2] = (char)('0' + r % 10);
							write_all(2, b, 3);
						}
						eput("\n");
					} else if (r != 0) {
						eput("transcriber: send failed\n");
					}
				}
				close(mfd);
				session_drop();
			}
		}
		if (nev == 0) {
			/* all inputs gone: rescan until one reappears, never exit */
			while ((nev = ev_autoscan(evfds)) == 0) {
				struct timespec ts = { 1, 0 };
				nanosleep(&ts, 0);
			}
			eput("transcriber: input recovered\n");
			for (int i = 0; i < nev; i++) {
				pf[i].fd = evfds[i];
				pf[i].events = POLLIN;
			}
		}
	}
	return 0;
}
