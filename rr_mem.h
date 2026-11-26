/* rr_mem.h - Driver transport and target-memory access for ROB RUN.
 *
 * The client opens a WmPort device, obtains its session key and exchanges
 * METHOD_BUFFERED IOCTL requests. Helpers locate modules through the target
 * PEB and loader list, including GameAssembly.dll. Windows structure offsets
 * used by those helpers are layout assumptions for the supported x64 build;
 * verify them when changing Windows versions.
 */
#ifndef RR_MEM_H
#define RR_MEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backend selection. The driver path (WmPort/kd2) relies on BYOVD mapping,
 * which Windows 11 with WHQL_ENFORCEMENT_MODE on refuses. RPM uses OpenProcess
 * + ReadProcessMemory/WriteProcessMemory, which is userspace and works on any
 * target that allows a handle with the needed rights. AUTO tries driver first
 * and falls back to RPM. Set once at startup, before rr_drv_open(). */
enum {
    RR_BACKEND_AUTO   = 0,   /* driver preferred, RPM fallback when driver absent */
    RR_BACKEND_DRIVER = 1,   /* fail if driver is not mapped                      */
    RR_BACKEND_RPM    = 2    /* userspace only, never touch the driver            */
};
void rr_set_backend(int backend);
int  rr_backend_active(void);    /* RR_BACKEND_DRIVER or RR_BACKEND_RPM after open */

/* Lifecycle. */
int  rr_drv_open(void);          /* 1 = transport ready for current backend  */
void rr_drv_close(void);
int  rr_drv_live(void);          /* 1 = a successful read happened           */
int  rr_drv_ready(void);         /* 1 = transport ready for current backend  */

/* Request process hiding (hide != 0) or restoration (hide == 0) through
 * WM_IO_VEIL. Return 1 if the driver accepts the request, otherwise 0.
 * Callers must check the result; acceptance alone does not verify visibility.
 */
int  rr_drv_hide_process(uint32_t pid, int hide);

/* Raw access: each individual request is limited to 64 KiB. */
int  rr_read (uint64_t addr, void* out, size_t n);

/* Read up to 64 address/size/destination items per call. Requests exceeding
 * the reply budget are split. Return the successful-item count, zero for an
 * invalid/empty request, or -1 for an incompatible or unsuccessful batch reply.
 * Only successful items are copied; callers can retry with rr_read().
 */
typedef struct RR_RD_REQ {
    uint64_t addr;
    uint32_t size;
    void*    dst;
} RR_RD_REQ;
int  rr_read_batch(RR_RD_REQ* items, int n);
extern long g_batch_status, g_batch_info, g_batch_expected;
int  rr_write(uint64_t addr, const void* in, size_t n);

/* One memory-region descriptor for a target address (WM_IO_REGION). */
typedef struct RR_REGION {
    uint64_t base, size;
    uint32_t state, protect, type;
} RR_REGION;
int  rr_query_region(uint64_t addr, RR_REGION* out);

/* Allocate memory in the specified process through WM_IO_ALLOC.
 * protect is a Windows page-protection value, such as 0x04 (read/write),
 * 0x20 (execute/read), or 0x40 (execute/read/write).
 * Return 1 on success and store the target address in *out.
 */
int  rr_drv_alloc_remote(uint32_t pid, size_t size, uint32_t protect, uint64_t* out);

/* Read a thread's user-mode context (read-only in the driver).
 * Returns 0 on success and fills *out, else the driver status. */
typedef struct RR_THREAD_CTX {
    uint64_t rip, rsp, rbp, rflags;
    uint32_t tid, ok;
} RR_THREAD_CTX;
long rr_drv_get_context(uint32_t thread_id, RR_THREAD_CTX* out);

/* Small-read helpers return zero on failure. Check rr_ok() to distinguish
 * a failed read from a successfully read zero.
 */
uint64_t rr_u64(uint64_t addr);
uint32_t rr_u32(uint64_t addr);
int32_t  rr_i32(uint64_t addr);
float    rr_f32(uint64_t addr);
int      rr_ok(void);            /* 1 = the last small read succeeded        */

/* Target process. */
extern uint32_t g_rr_pid;
int      rr_attach(const char* exe_name);   /* 0 = not running              */
void     rr_force_pid(uint32_t pid);        /* attach to an exact pid      */
/* Return 1 if the PID appears in the process snapshot, 0 if absent, or
 * -1 if enumeration fails. A failed snapshot is not evidence of absence.
 */
int      rr_process_visible(uint32_t pid);
uint64_t rr_image_base(void);               /* PEB->ImageBaseAddress        */
uint64_t rr_peb(void);                      /* Cached target PEB address. */

/* Module lookup through the target PEB. name is case-insensitive, e.g.
 * "GameAssembly.dll". On success *base is the loaded base and *size the
 * SizeOfImage from the LDR entry. */
int rr_module(const char* name, uint64_t* base, uint32_t* size);

/* Enumerates the target's loaded modules (same LDR walk). names is a flat
 * buffer of max entries x 64 bytes. Returns the number written. Used by
 * --probe to show that the PEB walk is alive even when no IL2CPP module is
 * present in the target. */
int rr_modules(char* names, uint64_t* bases, uint32_t* sizes, int max);

/* Pattern scan over a module image. */
/* Pattern mask: x matches a fixed byte and ? matches any byte. Return
 * the number of hits, up to max_hits, and fill hits[] with absolute addresses.
 */
int rr_scan(uint64_t start, uint64_t size, const uint8_t* pat, const char* mask,
            uint64_t* hits, int max_hits);

/* Diagnostics. */
long rr_stat_calls(void);        /* IOCTLs since the last reset              */
long rr_stat_bytes(void);
void rr_stat_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* RR_MEM_H */

