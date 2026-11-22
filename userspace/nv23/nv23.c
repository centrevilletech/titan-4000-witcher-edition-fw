/* witcher-nv23: read or write the Titan 4000 firmware bank table (NV item 23).
 *
 * The vendor keeps the bank table in NV item 23 of the cmnnv partition. Every
 * vendor flash and bank switch goes through nv_write(23, ...) in libnvm.so.
 * This helper does the same, for the boot-confirm bank guard in
 * titan-pd-keeper. It has no policy of its own: the keeper builds and checks
 * the 360-byte table, and reads the flash back afterwards.
 *
 *   witcher-nv23 read    the vendor view (RAM copy) of NV 23, 360 bytes, stdout
 *   witcher-nv23 write   exactly 360 bytes on stdin, one nv_write(23, ...)
 *
 * The write takes the vendor updater's token lock first, so it cannot run in
 * the middle of a firmware update. One nv_write is one cmnnv block program to
 * the older of the two NV copies, so a power cut leaves the old table or the
 * new one. Exit codes: 0 done, 64 usage, 65 bad input, 74 vendor call failed,
 * 75 the updater holds the lock, 77 not root. */
extern unsigned int geteuid(void);
extern unsigned int alarm(unsigned int);
extern int strcmp(const char *, const char *);
extern int read(int, void *, unsigned int);
extern int write(int, const void *, unsigned int);
extern int nv_read(unsigned int, void *, unsigned int, unsigned int);
extern int nv_write(unsigned int, void *, unsigned int, unsigned int);
extern int Upgrade_AllocTokenLock(void);
extern int Upgrade_FreeTokenLock(void);

#define TABLE 360u

static int output(const unsigned char *p, unsigned int n) {
    while (n) {
        int k = write(1, p, n);
        if (k <= 0) return 74;
        p += k;
        n -= (unsigned int)k;
    }
    return 0;
}

/* Exactly TABLE bytes, then end of input. */
static int input(unsigned char *p) {
    unsigned int got = 0;
    unsigned char extra;
    while (got < TABLE) {
        int k = read(0, p + got, TABLE - got);
        if (k <= 0) return 65;
        got += (unsigned int)k;
    }
    return read(0, &extra, 1) == 0 ? 0 : 65;
}

int main(int argc, char **argv) {
    unsigned char table[TABLE];
    int result;
    if (argc != 2) return 64;
    if (geteuid() != 0) return 77;
    if (!strcmp(argv[1], "read")) {
        alarm(20);
        if (nv_read(23, table, 0, TABLE) != (int)TABLE) return 74;
        return output(table, TABLE);
    }
    if (!strcmp(argv[1], "write")) {
        alarm(30);
        if (input(table)) return 65;
        if (Upgrade_AllocTokenLock() != 0) return 75;
        /* 0 is success; the vendor skips the flash write when the RAM copy
         * already holds these bytes. The keeper checks the flash itself. */
        result = nv_write(23, table, 0, TABLE);
        Upgrade_FreeTokenLock();
        return result == 0 ? 0 : 74;
    }
    return 64;
}
