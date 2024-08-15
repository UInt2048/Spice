#include "jailbreak.h"
#include "kmem.h"

kptr_t find_proc(pid_t pid)
{
    kptr_t proc = kernproc;

    while (proc) {
        pid_t proc_pid = (pid_t)rk32(proc + OFFSET_PROC_PID);

        if (proc_pid == pid) {
            return proc;
        }

        proc = kread_kptr(proc + OFFSET_PROC_LE_PREV);
    }

    LOG("Failed to find proc");
    return 0x0;
}

kptr_t find_proc_by_name(const char* name)
{
    kptr_t proc = kernproc;

    while (proc) {
        char proc_name[40] = { 0 };

        kread(proc + OFFSET_PROC_NAME, proc_name, sizeof(proc_name));

        if (strncmp(proc_name, name, sizeof(proc_name)) == 0) {
            return proc;
        }

        proc = kread_kptr(proc + OFFSET_PROC_LE_PREV);
    }

    LOG("Failed to find proc by name");
    return 0x0;
}

pid_t get_pid_for_name(const char* name)
{
    kptr_t proc = find_proc_by_name(name);
    if (proc == 0x0) {
        return 0;
    }

    return (pid_t)rk32(proc + OFFSET_PROC_PID);
}

kptr_t task_self_addr(void)
{
    kptr_t self_proc = find_proc(getpid());
    LOG("got self_proc = %llx\n", self_proc);

    return rk64(self_proc + OFFSET_PROC_TASK);
}

kptr_t find_port_address(mach_port_name_t port)
{
    kptr_t task_port_addr = task_self_addr();

    kptr_t itk_space = kread_kptr(task_port_addr + OFFSET_TASK_ITK_SPACE); // task_t::itk_space

    kptr_t is_table = kread_kptr(itk_space + OFFSET_ITK_SPACE_IS_TABLE);

    // This offset is static, see the CVE-2016-7637 writeup:
    // https://papers.put.as/papers/ios/2017/Through_the_mach_portal.pdf
    uint32_t port_index = port >> 8;

    return kread_kptr(is_table + (port_index * SIZEOF_IPC_ENTRY_T));
}
