#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#define WAV_HDR_SIZE 44
#define SAMPLE_RATE 16000
#define CHANNELS 1

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
        int got = 0;
        for (size_t i=line_start;i<hex_end;i++) {
            int v = hex_val(body[i]);
            if (v < 0) {
                if (body[i]==' '||body[i]=='\t') continue;
                return -1;
            }
            got = 1;
            chunk_size = (chunk_size<<4) | (size_t)v;
        }
        if (!got) return -1;
        src++;
        if (chunk_size == 0) break;
        if (src + chunk_size > blen) return -1;
        memmove(body+dst, body+src, chunk_size);
        dst += chunk_size;
        src += chunk_size;
        if (src < blen && body[src] == '\r') src++;
        if (src < blen && body[src] == '\n') src++;
    }
    return (ssize_t)dst;
}

typedef struct { int channels; int32_t acc; int pending; int16_t raw[2048]; } Resampler;
static void resampler_feed(Resampler *rs, int16_t *in, size_t in_samples_or_frames, int16_t *out, size_t *out_written, size_t cap) {
    int32_t acc = rs->acc;
    int pending = rs->pending;
    size_t written = 0;
    if (rs->channels == 1) {
        size_t i=0;
        while (pending && i < in_samples_or_frames && written < cap) {
            acc += in[i++];
            if (++pending == 3) { out[written++] = (int16_t)(acc/3); acc=0; pending=0; }
        }
        while (i + 3 <= in_samples_or_frames && written < cap) {
            int32_t s = (int32_t)in[i] + in[i+1] + in[i+2];
            out[written++] = (int16_t)(s/3);
            i+=3;
        }
        while (i < in_samples_or_frames && written < cap) { acc+=in[i++]; pending++; }
    } else {
        size_t frames = in_samples_or_frames;
        int16_t *s = in;
        size_t i=0;
        while (pending && i < frames && written < cap) {
            acc += (s[2*i] + s[2*i+1])/2;
            i++;
            if (++pending==3){ out[written++]=(int16_t)(acc/3); acc=0; pending=0; }
        }
        while (i+3 <= frames && written < cap) {
            int32_t m0 = (s[2*i] + s[2*i+1])/2;
            int32_t m1 = (s[2*i+2] + s[2*i+3])/2;
            int32_t m2 = (s[2*i+4] + s[2*i+5])/2;
            out[written++] = (int16_t)((m0+m1+m2)/3);
            i+=3;
        }
        while (i < frames && written < cap){ acc+=(s[2*i]+s[2*i+1])/2; i++; pending++; }
    }
    rs->acc=acc; rs->pending=pending;
    *out_written=written;
}

static int contains_crlf(const char *s){ return strchr(s,'\r')||strchr(s,'\n'); }
static int has_control(const char *s){ for(const unsigned char *p=(const unsigned char*)s;*p;p++) if(*p<0x20||*p==0x7f) return 1; return 0; }
static int is_valid_host(const char *s){
    if(!s||!*s) return 0;
    if(contains_crlf(s)||has_control(s)) return 0;
    if(strchr(s,'/')||strchr(s,' ')||strchr(s,':')||strchr(s,'@')) return 0;
    for(size_t i=0;s[i];i++){ char c=s[i]; if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_')) return 0; }
    return 1;
}

static void test_wav(void){
    uint8_t hdr[44];
    wav_fill_header(hdr, 0);
    assert(memcmp(hdr,"RIFF",4)==0);
    assert(memcmp(hdr+8,"WAVEfmt ",8)==0);
    assert(memcmp(hdr+36,"data",4)==0);
    uint32_t data_len=0;
    memcpy(&data_len, hdr+40,4);
    assert(data_len==0);
    wav_fill_header(hdr, 16000*2);
    memcpy(&data_len, hdr+40,4);
    assert(data_len==32000);
    uint32_t riff_len; memcpy(&riff_len, hdr+4,4);
    assert(riff_len==36+32000);
    printf("PASS wav header\n");
}

static void test_json(void){
    char out[4096];
    const char *j1 = "{\"text\":\"hello world\"}";
    int r = json_extract_text(j1, strlen(j1), out, sizeof(out));
    assert(r>0 && strcmp(out,"hello world")==0);
    const char *j2 = "{\"something\":123,\"text\":\"line\\nbreak\",\"other\":{}}";
    r = json_extract_text(j2, strlen(j2), out, sizeof(out));
    assert(r>0 && strcmp(out,"line\nbreak")==0);
    const char *j3 = "{\"text\":\"unicode \\u00e9 test\"}";
    r = json_extract_text(j3, strlen(j3), out, sizeof(out));
    assert(r>0);
    const char *j4 = "{\"text\":\"quote \\\"inside\\\"\"}";
    r = json_extract_text(j4, strlen(j4), out, sizeof(out));
    assert(r>0 && strstr(out,"quote")!=NULL);
    const char *j5 = "{\"nope\":\"nothing\"}";
    r = json_extract_text(j5, strlen(j5), out, sizeof(out));
    assert(r==-1);
    printf("PASS json parser\n");
}

static void test_resampler_mono(void){
    Resampler rs = {1,0,0,{0}};
    int16_t in[9] = {3000,3000,3000, 6000,6000,6000, 9000,9000,9000};
    int16_t out[10]={0};
    size_t written=0;
    resampler_feed(&rs, in, 9, out, &written, 10);
    assert(written==3);
    assert(out[0]==3000 && out[1]==6000 && out[2]==9000);
    printf("PASS resampler mono 3:1\n");
}

static void test_resampler_stereo(void){
    Resampler rs = {2,0,0,{0}};

    int16_t in[12] = {1000,3000, 1000,3000, 1000,3000, 4000,8000, 4000,8000, 4000,8000};
    int16_t out[10]={0};
    size_t written=0;
    resampler_feed(&rs, in, 6, out, &written, 10);
    assert(written==2);

    assert(out[0]==2000 && out[1]==6000);
    printf("PASS resampler stereo 48k->16k\n");
}

static void test_chunked(void){
    char buf[256];
    strcpy(buf, "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n");
    ssize_t len = http_decode_chunked(buf, strlen(buf));
    assert(len==11);
    buf[len]=0;
    assert(strcmp(buf,"Hello World")==0);
    strcpy(buf, "A; ext\r\n1234567890\r\n0\r\n\r\n");
    len = http_decode_chunked(buf, strlen(buf));
    assert(len==10);
    printf("PASS chunked decoding\n");
}

static void test_env_validation(void){
    assert(is_valid_host("api.groq.com"));
    assert(!is_valid_host("api.groq.com\r\nInject: evil"));
    assert(!is_valid_host("api.groq.com\n"));
    assert(!is_valid_host("api.groq.com/evil"));
    assert(!is_valid_host("api.groq.com:443"));
    assert(!is_valid_host(""));
    assert(contains_crlf("bad\r\n"));
    assert(has_control("bad\x01"));
    printf("PASS env validation\n");
}

int main(void){
    test_wav();
    test_json();
    test_resampler_mono();
    test_resampler_stereo();
    test_chunked();
    test_env_validation();
    printf("ALL TESTS PASSED\n");
    return 0;
}
