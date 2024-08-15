#import <CoreFoundation/CoreFoundation.h>

#include "common.h"
#include "iokit.h"
#include "kmem.h"
#include "kutils.h"
#include "nonce.h"

kptr_t iodtnvram_obj = 0x0;
kptr_t original_vtab = 0x0;

kern_return_t set_generator(const char* new_generator)
{
    kern_return_t ret = KERN_SUCCESS;

    const char* current_generator = get_generator();
    LOG("got current generator: %s", current_generator);

    if (current_generator != NULL) {
        if (strcmp(current_generator, new_generator) == 0) {
            LOG("not setting new generator -- generator is already set");
            free((void*)current_generator);
            return KERN_SUCCESS;
        }

        free((void*)current_generator);
    }

    CFStringRef str = CFStringCreateWithCStringNoCopy(NULL, new_generator, kCFStringEncodingUTF8, kCFAllocatorNull);
    if (str == NULL) {
        LOG("failed to allocate new CFStringRef");
        return KERN_FAILURE;
    }

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (dict == NULL) {
        LOG("failed to allocate new CFMutableDictionaryRef");
        return KERN_FAILURE;
    }

    CFDictionarySetValue(dict, CFSTR("com.apple.System.boot-nonce"), str);
    CFRelease(str);

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(nvram)) {
        LOG("failed to open IODTNVRAM service");
        return KERN_FAILURE;
    }

    ret = IORegistryEntrySetCFProperties(nvram, dict);

    return ret;
}

const char* get_generator()
{
    kern_return_t ret = KERN_SUCCESS;

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(nvram)) {
        LOG("failed to open IODTNVRAM service");
        return NULL;
    }

    io_string_t buffer;
    unsigned int len = 256;
    ret = IORegistryEntryGetProperty(nvram, "com.apple.System.boot-nonce", buffer, &len);
    if (ret != KERN_SUCCESS) {
        // Nonce is not set
        LOG("nonce is not currently set");
        return NULL;
    }

    return strdup(buffer);
}

kern_return_t unlock_nvram()
{
    io_service_t iodtnvram_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if (iodtnvram_service == MACH_PORT_NULL) {
        LOG("failed to open IODTNVRAM service");
        return KERN_FAILURE;
    }

    kptr_t port_addr = find_port_address(iodtnvram_service);
    if (port_addr == 0x0) {
        LOG("failed to find IODTNVRAM port");
        return KERN_FAILURE;
    }

    iodtnvram_obj = kread_kptr(port_addr + OFFSET_IPC_PORT_IP_KOBJECT);
    if (iodtnvram_obj == 0x0) {
        LOG("failed ot read IODTNVRAM obj");
        return KERN_FAILURE;
    }

    original_vtab = kread_kptr(iodtnvram_obj);
    if (original_vtab == 0x0) {
        LOG("failed to find IODTNVRAM obj vtab");
        return KERN_FAILURE;
    }

    kptr_t* vtab_buf = malloc(OFFSET_VTAB_SIZE);
    kread(original_vtab, (void*)vtab_buf, OFFSET_VTAB_SIZE);

    vtab_buf[OFFSET_GET_OF_VARIABLE_PERM / sizeof(kptr_t)] = vtab_buf[OFFSET_SEARCH_NVRAM_PROP / sizeof(kptr_t)];

    kptr_t fake_vtable = kalloc(OFFSET_VTAB_SIZE);
    kwrite(fake_vtable, (void*)vtab_buf, OFFSET_VTAB_SIZE);

    // patch vtable
    kwrite_kptr(iodtnvram_obj, fake_vtable);

    free((void*)vtab_buf);

    LOG("patched nvram checks");

    return KERN_SUCCESS;
}

kern_return_t lock_nvram()
{
    if (iodtnvram_obj == 0x0) {
        LOG("failed to find iodtnvram_obj to lock down");
        return KERN_FAILURE;
    }

    if (original_vtab == 0x0) {
        LOG("failed to find original vtab to lock back down to");
        return KERN_FAILURE;
    }

    wk64(iodtnvram_obj, original_vtab);

    LOG("locked down nvram");

    return KERN_SUCCESS;
}
