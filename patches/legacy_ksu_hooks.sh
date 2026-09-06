#!/bin/bash
# KernelSU-Next (v3.2.0-legacy) manual syscall hooks for pre-GKI kernels.
#
# Rewritten for the KernelSU-Next hook API. The stock script shipped by
# KernelSU_Action targets the legacy KernelSU 0.9.x API (ksu_handle_vfs_read,
# no reboot hook, hook-bool guard), which KernelSU-Next >= v3.2.0-legacy no
# longer recognises -- its Kbuild aborts with:
#   "No hooks were defined, please integrate manual hooks in your kernel!"
#
# Follows the official KernelSU-Next non-GKI integration guide:
#   https://kernelsu-next.github.io/webpage/pages/how-to-integrate-for-non-gki.html
# Hooks: ksu_handle_execveat / ksu_handle_faccessat / ksu_handle_sys_read /
#        ksu_handle_stat / ksu_handle_sys_reboot
# Anchors verified against LineageOS/android_kernel_oneplus_sdm845
# lineage-18.1 (msm-4.9, OnePlus 6 enchilada).
# NOTE: sed addresses must not contain a raw '{' (GNU sed treats it as a
#       command-group opener and aborts the script), so the exec.c envp hook
#       anchor is matched by prefix without the brace. Inserted text uses \n
#       escapes (GNU extension); the closing '}' of a { } group must sit on
#       its own line, never after an a/i text.
# Idempotent: a file is skipped once it already contains ksu_handle.

set -euo pipefail

patch_files=(
    fs/exec.c
    fs/open.c
    fs/read_write.c
    fs/stat.c
    kernel/reboot.c
)

for i in "${patch_files[@]}"; do
    if [ ! -f "$i" ]; then
        echo "Warning: $i not found; skipping"
        continue
    fi
    if grep -q "ksu_handle" "$i"; then
        echo "Warning: $i already contains KernelSU hooks; skipping"
        continue
    fi
    echo "Patching $i"

    case $i in

    # ------------------------------------------------------------ fs/exec.c
    fs/exec.c)
        # 1) extern declaration before do_execve()
        sed -i '/^int do_execve(struct filename \*filename,$/i\#ifdef CONFIG_KSU\n__attribute__((hot))\nextern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n				void *argv, void *envp, int *flags);\n#endif\n' fs/exec.c
        # 2) hook call inside do_execve(), right after its envp initialiser
        sed -i '/^int do_execve(struct filename \*filename,$/,/^	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);$/{
/^\tstruct user_arg_ptr envp = /a\#ifdef CONFIG_KSU\n	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n#endif\n
}' fs/exec.c
        # 3) hook call inside compat_do_execve() (32-bit su / 32-on-64)
        sed -i '/^static int compat_do_execve(/,/^	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);$/{
/\.ptr\.compat = __envp,/,/^\t};$/{
/^\t};$/a\#ifdef CONFIG_KSU\n	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n#endif\n
}
}' fs/exec.c
        # 4) hook call inside do_execveat() — 64-bit execveat(2) path used by A11 bionic
        sed -i '/^int do_execveat(int fd, struct filename \*filename,$/,/^	return do_execveat_common(fd, filename, argv, envp, flags);$/{
/^\tstruct user_arg_ptr envp = /a\#ifdef CONFIG_KSU\n	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n#endif\n
}' fs/exec.c
        # 5) hook call inside compat_do_execveat() — 32-bit execveat on 64-bit kernel
        sed -i '/^static int compat_do_execveat(int fd, struct filename \*filename,$/,/^	return do_execveat_common(fd, filename, argv, envp, flags);$/{
/\.ptr\.compat = __envp,/,/^\t};$/{
/^\t};$/a\#ifdef CONFIG_KSU\n	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n#endif\n
}
}' fs/exec.c
        ;;

    # ------------------------------------------------------------ fs/open.c
    fs/open.c)
        # extern declaration before SYSCALL_DEFINE3(faccessat, ...)
        sed -i '/^ \* access() needs to use the real uid\/gid, not the effective uid\/gid\./,/^SYSCALL_DEFINE3(faccessat, int, dfd, const char __user \*, filename, int, mode)$/{
/^SYSCALL_DEFINE3(faccessat, int, dfd, const char __user \*, filename, int, mode)$/i\#ifdef CONFIG_KSU\n__attribute__((hot))\nextern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n				int *mode, int *flags);\n#endif\n
}' fs/open.c
        # hook call after 'unsigned int lookup_flags = LOOKUP_FOLLOW;'
        sed -i '/^SYSCALL_DEFINE3(faccessat, int, dfd, const char __user \*, filename, int, mode)$/,/if (mode & ~S_IRWXO)/{
/^\tunsigned int lookup_flags = LOOKUP_FOLLOW;$/a\#ifdef CONFIG_KSU\n	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n#endif\n
}' fs/open.c
        ;;

    # ------------------------------------------------------ fs/read_write.c
    fs/read_write.c)
        # extern declarations before SYSCALL_DEFINE3(read, ...)
        sed -i '/^SYSCALL_DEFINE3(read, unsigned int, fd, char __user \*, buf, size_t, count)$/i\#ifdef CONFIG_KSU\nextern bool ksu_vfs_read_hook __read_mostly;\nextern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,\n				char __user **buf_ptr, size_t *count_ptr);\n#endif\n' fs/read_write.c
        # hook call right after 'struct fd f = fdget_pos(fd);' in read()
        sed -i '/^SYSCALL_DEFINE3(read, unsigned int, fd, char __user \*, buf, size_t, count)$/,/^	if (f.file) {/{
/^\tstruct fd f = fdget_pos(fd);$/a\#ifdef CONFIG_KSU\n	if (unlikely(ksu_vfs_read_hook))\n		ksu_handle_sys_read(fd, &buf, &count);\n#endif\n
}' fs/read_write.c
        ;;

    # ------------------------------------------------------------ fs/stat.c
    fs/stat.c)
        # extern declaration before the newfstatat block
        sed -i '/^#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)$/i\#ifdef CONFIG_KSU\n__attribute__((hot))\nextern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n				int *flags);\n#endif\n' fs/stat.c
        # hook call after 'int error;' in newfstatat()
        sed -i '/^SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user \*, filename,$/,/^	error = vfs_fstatat(dfd, filename, &stat, flag);$/{
/^\tint error;$/a\#ifdef CONFIG_KSU\n	ksu_handle_stat(&dfd, &filename, &flag);\n#endif\n
}' fs/stat.c
        ;;

    # ------------------------------------------------------- kernel/reboot.c
    kernel/reboot.c)
        # extern declaration before SYSCALL_DEFINE4(reboot, ...)
        sed -i '/^SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,$/i\#ifdef CONFIG_KSU\nextern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n#endif\n' kernel/reboot.c
        # hook call after 'int ret = 0;' in reboot()
        sed -i '/^SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,$/,/^	\/\* We only trust the superuser with rebooting the system\. \*\//{
/^\tint ret = 0;$/a\#ifdef CONFIG_KSU\n	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n#endif\n
}' kernel/reboot.c
        ;;

    esac
done

# ------------------------------------------------------- security/selinux/hooks.c
# Allow init -> ksu bounded domain transition (Android 11+ NNP/nosuid blocks it)
if [ -f security/selinux/hooks.c ]; then
    if ! grep -q "is_ksu_transition" security/selinux/hooks.c; then
        echo "Patching security/selinux/hooks.c"
        # extern declaration before check_nnp_nosuid()
        sed -i '/^static int check_nnp_nosuid(/i\#ifdef CONFIG_KSU\nextern bool is_ksu_transition(const struct task_security_struct *old_tsec,\n\t\t      const struct task_security_struct *new_tsec);\n#endif\n' security/selinux/hooks.c
        # early return for init -> ksu transition, skip security_bounded_transition()
        sed -i '/No change in credentials/a\#ifdef CONFIG_KSU\n\tif (is_ksu_transition(old_tsec, new_tsec))\n\t\treturn 0;\n#endif\n' security/selinux/hooks.c
    else
        echo "Warning: security/selinux/hooks.c already contains is_ksu_transition; skipping"
    fi
fi

# ------------------------------------------------------- KernelSU/kernel/runtime/boot_event.c
# Fix FBE race: observer triggers first track_throne at ~12s before user
# unlocks /data/app (CE storage), so is_manager_apk() filp_open fails and
# manager is never crowned. on_boot_completed() then calls track_throne(true)
# which is prune-only (no re-search). Change to track_throne(false) so
# boot_completed re-scans /data/app after unlock.
if [ -f KernelSU/kernel/runtime/boot_event.c ]; then
    if ! grep -q "track_throne(false)" KernelSU/kernel/runtime/boot_event.c; then
        echo "Patching KernelSU/kernel/runtime/boot_event.c (track_throne false)"
        sed -i 's/track_throne(true)/track_throne(false)/' KernelSU/kernel/runtime/boot_event.c
    else
        echo "Warning: boot_event.c already has track_throne(false); skipping"
    fi
else
    echo "Warning: KernelSU/kernel/runtime/boot_event.c not found; skipping"
fi

echo "KernelSU-Next manual hooks applied."
