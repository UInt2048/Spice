#include <stdlib.h>

#include "common.h"
#include "cs_blobs.h"
#include "kents.h"
#include "kmem.h"
#include "kutils.h"

kptr_t find_csblobs(int pid)
{
    kptr_t proc = find_proc(pid);
    if (proc == 0x0) {
        LOG("failed to find proc for pid %d", pid);
        return 0;
    }

    kptr_t textvp = kread_kptr(proc + OFFSET_PROC_P_TEXTVP); // proc->p_textvp
    if (textvp == 0x0) {
        LOG("failed to find textvp for pid %d", pid);
        return 0;
    }

    kptr_t ubcinfo = kread_kptr(textvp + OFFSET_VNODE_V_UBCINFO); // vnode->v_ubcinfo
    if (ubcinfo == 0x0) {
        LOG("failed to find ubcinfo for pid %d", pid);
        return 0;
    }

    return kread_kptr(ubcinfo + OFFSET_UBCINFO_CSBLOBS); // ubc_info->csblobs
}

const char* get_current_entitlements(int pid)
{
    kptr_t csblob = find_csblobs(pid);
    if (csblob == 0x0) {
        LOG("failed to find csblob for pid %d", pid);
        return NULL;
    }

    kptr_t csb_entitlements_blob = kread_kptr(csblob + OFFSET_CSBLOB_CSB_ENTITLEMENTS_BLOB); // cs_blob->csb_entitlements_blob
    if (csb_entitlements_blob == 0x0) {
        LOG("failed to find csb_entitlements_blob for pid %d", pid);
        return NULL;
    }

    uint32_t blob_length = ntohl(rk32(csb_entitlements_blob + OFFSET_CSBLOB_LENGTH));
    if (blob_length == 0x0) {
        LOG("got blob length of 0 for pid %d", pid);
        return NULL;
    }

    // skip the header, just get the data
    blob_length -= OFFSET_CSBLOB_DATA;

    const char* ent_string = (const char*)malloc(blob_length);
    kread(csb_entitlements_blob + OFFSET_CSBLOB_DATA, (void*)ent_string, blob_length);

    return ent_string;
}

int assign_new_entitlements(int pid, const char* new_ents)
{
    kptr_t csblob = find_csblobs(pid);
    if (csblob == 0x0) {
        LOG("failed to find csblob for pid %d", pid);
        return -1;
    }

    int new_blob_length = OFFSET_CSBLOB_DATA + (int)strlen(new_ents) + 0x1;

    CS_GenericBlob* new_blob = (CS_GenericBlob*)malloc(new_blob_length);
    new_blob->magic = ntohl(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    new_blob->length = ntohl(new_blob_length);

    strncpy(new_blob->data, new_ents, strlen(new_ents) + 1);

    kptr_t blob_kern = kalloc(new_blob_length);
    if (blob_kern == 0x0) {
        LOG("failed to alloc %d bytes for new ent blob", new_blob_length);
        return -1;
    }

    kwrite(blob_kern, new_blob, new_blob_length);

    free(new_blob);

    kwrite_kptr(csblob + OFFSET_CSBLOB_CSB_ENTITLEMENTS_BLOB, blob_kern);

    return 0;
}
