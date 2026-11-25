/* at_obf.h - lightweight anti-reverse helpers for Logit.
 *
 * Three families (all header-only):
 *   1. String decryption : runtime XOR-decode of baked-in encrypted arrays.
 *   2. API hashing       : resolve DLL exports by name-hash, never by import.
 *   3. Opaque predicates : noise branches that always evaluate the same way
 *                          but that static analysis (incl. LLMs) can't prove.
 *
 * The goal is not perfect secrecy - it's to burn an LLM's budget. A human
 * expert with a debugger still gets through; an AI reading decompilation
 * alone gives up or hallucinates.
 */
#ifndef AT_OBF_H
#define AT_OBF_H

#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include <winternl.h>

/* --- string decryption ------------------------------------------------- */

#define AT_XKEY 0x5A

static __forceinline void at_xor_decrypt(const unsigned char* src, char* dst, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) dst[i] = (char)(src[i] ^ AT_XKEY);
    dst[n] = 0;
}

/* --- API resolution by hash ------------------------------------------- */

/* djb2a hash, case-insensitive on name bytes (lower/upper handled by the
 * caller's HASH() macro values). */
static __forceinline uint32_t at_hash_str(const char* s) {
    uint32_t h = 5381u;
    unsigned char c;
    while (*s) {
        c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h = ((h << 5) + h) ^ c;
    }
    return h;
}

/* Walk ntdll-loaded module list via PEB to avoid LoadLibraryA import, then
 * parse the export table manually. */
typedef struct _AT_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoad;
    LIST_ENTRY InMemory;
    LIST_ENTRY InInit;
    void*  DllBase;
    void*  EntryPoint;
    ULONG  SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} AT_LDR_DATA_TABLE_ENTRY;

static void* at_find_module_by_hash(uint32_t name_hash) {
    PPEB peb;
    PPEB_LDR_DATA ldr;
    PLIST_ENTRY head, cur;
    AT_LDR_DATA_TABLE_ENTRY* e;
    char name[128];
    size_t i, j;
    wchar_t wc;
    char c;

    peb = (PPEB)__readgsqword(0x60);
    ldr = peb->Ldr;
    head = &ldr->InMemoryOrderModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        e = (AT_LDR_DATA_TABLE_ENTRY*)
            ((char*)cur - offsetof(AT_LDR_DATA_TABLE_ENTRY, InMemory));
        j = 0;
        if (!e->BaseDllName.Buffer) continue;
        for (i = 0; i < (size_t)(e->BaseDllName.Length / 2) && j < 127; ++i) {
            wc = e->BaseDllName.Buffer[i];
            c = (wc < 128) ? (char)wc : '?';
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            name[j++] = c;
        }
        name[j] = 0;
        if (at_hash_str(name) == name_hash) return e->DllBase;
    }
    return NULL;
}

static void* at_find_export_by_hash(void* module_base, uint32_t fn_hash) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    IMAGE_DATA_DIRECTORY ed;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD *names, *funcs;
    WORD  *ords;
    DWORD i;
    const char *n, *p;
    uint32_t h;

    if (!module_base) return NULL;
    dos = (PIMAGE_DOS_HEADER)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (PIMAGE_NT_HEADERS)((char*)module_base + dos->e_lfanew);
    ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return NULL;
    exp = (PIMAGE_EXPORT_DIRECTORY)((char*)module_base + ed.VirtualAddress);
    names = (DWORD*)((char*)module_base + exp->AddressOfNames);
    ords  = (WORD*) ((char*)module_base + exp->AddressOfNameOrdinals);
    funcs = (DWORD*)((char*)module_base + exp->AddressOfFunctions);
    for (i = 0; i < exp->NumberOfNames; ++i) {
        n = (const char*)module_base + names[i];
        h = 5381u;
        for (p = n; *p; ++p) h = ((h << 5) + h) ^ (unsigned char)*p;
        if (h == fn_hash) return (char*)module_base + funcs[ords[i]];
    }
    return NULL;
}

#define AT_RESOLVE(dll_hash, fn_hash) \
    at_find_export_by_hash(at_find_module_by_hash((dll_hash)), (fn_hash))

/* --- opaque predicates / junk ---------------------------------------- */

/* Always true at runtime but a static analyzer can't prove it (depends on
 * runtime tick count & memory contents). */
#define AT_OPAQUE_TRUE \
    (((GetTickCount() | 0x80000001u) != 0u) && \
     ((size_t)(&_AT_junk_sink) != 0u))

extern volatile int _AT_junk_sink;

/* Scatters bogus computation + a never-taken branch pointing at a crash to
 * mislead patch attempts. */
#define AT_JUNK(seed) do {                                               \
    volatile unsigned int _j = (unsigned int)(seed) * 2654435761u + 7u;  \
    _AT_junk_sink ^= (int)_j;                                            \
    if (!AT_OPAQUE_TRUE) { *(volatile int*)0 = 0xDEAD; }                 \
} while (0)

#endif /* AT_OBF_H */
