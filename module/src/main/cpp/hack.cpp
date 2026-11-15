//
// Created by Perfare on 2020/7/4.
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <climits>

// ---- decrypted global-metadata.dat save (Digimon-NC) ------------------------------------------
// The game decrypts global-metadata.dat into RAM during il2cpp_init; dump_metadata saves it.
static uint32_t md_header_length(const uint8_t *h, size_t avail) {
    if (avail < 12 || *(const uint32_t *) h != 0xFAB11BAFu) return 0;
    int32_t version = *(const int32_t *) (h + 4);
    if (version < 16 || version > 40) return 0;
    int32_t hb = *(const int32_t *) (h + 8);
    if (hb < 0x40 || hb > 0x400 || (hb - 8) % 8 != 0 || (size_t) hb > avail) return 0;
    int64_t length = 0;
    const int64_t max_bytes = 512LL * 1024 * 1024;
    for (int i = 0; i < (hb - 8) / 8; i++) {
        int32_t o = *(const int32_t *) (h + 8 + i * 8);
        int32_t sz = *(const int32_t *) (h + 12 + i * 8);
        if (o < 0 || sz < 0 || sz > max_bytes) return 0;
        if (sz && o < hb) return 0;
        if ((int64_t) o + sz > max_bytes) return 0;
        if ((int64_t) o + sz > length) length = (int64_t) o + sz;
    }
    if (length < hb) return 0;
    return (uint32_t) length;
}

static bool safe_read(const void *addr, void *buf, size_t len) {
    // process_vm_readv on our own pid: unmapped/unreadable pages give EFAULT instead of SIGSEGV.
    struct iovec local = {buf, len};
    struct iovec remote = {const_cast<void *>(addr), len};
    return syscall(__NR_process_vm_readv, getpid(), &local, 1, &remote, 1, 0) == (ssize_t) len;
}

static void write_status(const char *game_data_dir, const char *text) {
    char out[PATH_MAX];
    snprintf(out, sizeof(out), "%s/files/dumper_status.txt", game_data_dir);
    FILE *f = fopen(out, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static void dump_metadata(const char *game_data_dir, void *il2cpp_handle) {
    // IL2CPP class names point into the decrypted metadata string table. Save the contiguous readable
    // region around that string (capped), and separately any blob in it with a valid IL2CPP header.
    typedef void *(*domain_get_t)();
    typedef void **(*domain_get_assemblies_t)(void *, size_t *);
    typedef void *(*assembly_get_image_t)(void *);
    typedef size_t (*image_get_class_count_t)(void *);
    typedef void *(*image_get_class_t)(void *, size_t);
    typedef const char *(*class_get_name_t)(void *);
    auto domain_get = (domain_get_t) xdl_sym(il2cpp_handle, "il2cpp_domain_get", nullptr);
    auto get_assemblies = (domain_get_assemblies_t) xdl_sym(il2cpp_handle, "il2cpp_domain_get_assemblies", nullptr);
    auto get_image = (assembly_get_image_t) xdl_sym(il2cpp_handle, "il2cpp_assembly_get_image", nullptr);
    auto class_count = (image_get_class_count_t) xdl_sym(il2cpp_handle, "il2cpp_image_get_class_count", nullptr);
    auto get_class = (image_get_class_t) xdl_sym(il2cpp_handle, "il2cpp_image_get_class", nullptr);
    auto class_name = (class_get_name_t) xdl_sym(il2cpp_handle, "il2cpp_class_get_name", nullptr);
    if (!domain_get || !get_assemblies || !get_image || !class_count || !get_class || !class_name) {
        LOGE("metadata: il2cpp api missing");
        write_status(game_data_dir, "error api-missing\n");
        return;
    }
    size_t n_asm = 0;
    void **assemblies = get_assemblies(domain_get(), &n_asm);
    uintptr_t anchor = 0;
    for (size_t a = 0; a < n_asm && !anchor; a++) {
        void *image = get_image(assemblies[a]);
        if (image && class_count(image) > 0) {
            void *klass = get_class(image, 0);
            if (klass) anchor = (uintptr_t) class_name(klass);
        }
    }
    if (!anchor) {
        LOGE("metadata: no anchor string");
        write_status(game_data_dir, "error no-anchor\n");
        return;
    }
    const uintptr_t page = (uintptr_t) sysconf(_SC_PAGESIZE);
    const uintptr_t cap = 384UL * 1024 * 1024;  // per direction
    std::vector<uint8_t> buf(page);
    uintptr_t lo = anchor & ~(page - 1), hi = lo;
    while (anchor - (lo - page) <= cap && safe_read((void *) (lo - page), buf.data(), page)) lo -= page;
    while (hi - anchor <= cap && safe_read((void *) hi, buf.data(), page)) hi += page;
    if (hi <= lo) {
        LOGE("metadata: anchor %p not readable", (void *) anchor);
        write_status(game_data_dir, "error anchor-unreadable\n");
        return;
    }
    LOGI("metadata: region %p-%p (%zu bytes), anchor +%zu", (void *) lo, (void *) hi, (size_t) (hi - lo),
         (size_t) (anchor - lo));

    char out[PATH_MAX];
    snprintf(out, sizeof(out), "%s/files/metadata_region_%lx_anchor_%lx.bin", game_data_dir,
             (unsigned long) lo, (unsigned long) anchor);
    FILE *f = fopen(out, "wb");
    if (!f) {
        LOGE("metadata: cannot write %s", out);
        write_status(game_data_dir, "error cannot-write\n");
        return;
    }
    int headers = 0;
    const size_t chunk = 1 << 20;
    std::vector<uint8_t> big(chunk + 0x400);
    for (uintptr_t at = lo; at < hi; at += chunk) {
        size_t n = std::min((size_t) (hi - at), chunk);
        if (!safe_read((void *) at, big.data(), n)) {
            LOGE("metadata: read failed at %p", (void *) at);
            break;
        }
        fwrite(big.data(), 1, n, f);
        for (size_t i = 0; i + 12 <= n; i += 4) {
            if (*(const uint32_t *) (big.data() + i) != 0xFAB11BAFu) continue;
            size_t avail = std::min((size_t) 0x400, (size_t) (hi - (at + i)));
            std::vector<uint8_t> hdr(avail);
            if (!safe_read((void *) (at + i), hdr.data(), avail)) continue;
            uint32_t length = md_header_length(hdr.data(), avail);
            if (length) {
                headers++;
                LOGI("metadata: header v%d length %u at %p", *(const int32_t *) (hdr.data() + 4), length,
                     (void *) (at + i));
            }
        }
    }
    fclose(f);
    LOGI("metadata: region saved -> %s (%d valid header(s))", out, headers);
    char status[128];
    snprintf(status, sizeof(status), "done region %zu headers %d\n", (size_t) (hi - lo), headers);
    write_status(game_data_dir, status);
    LOGI("metadata: 1 candidate(s) written");
}
// -----------------------------------------------------------------------------------------------

void hack_start(const char *game_data_dir) {
    bool load = false;
    for (int i = 0; i < 10; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            il2cpp_api_init(handle);
            write_status(game_data_dir, "dumping\n");
            il2cpp_dump(game_data_dir);
            write_status(game_data_dir, "metadata\n");
            dump_metadata(game_data_dir, handle);
            break;
        } else {
            sleep(1);
        }
    }
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    //TODO 等待houdini初始化
    sleep(5);

    // Android 10+: libart lives in the ART APEX namespace, so plain dlopen() from here fails.
    // xdl walks the already-loaded modules instead.
    auto libart = xdl_open("libart.so", XDL_DEFAULT);
    auto JNI_GetCreatedJavaVMs = libart ? (jint (*)(JavaVM **, jsize, jsize *)) xdl_sym(libart,
                                                                             "JNI_GetCreatedJavaVMs", nullptr) : nullptr;
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    if (!JNI_GetCreatedJavaVMs) {
        LOGE("JNI_GetCreatedJavaVMs not found");
        return false;
    }
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    void *nb = nullptr;
    auto native_bridge = GetNativeBridgeLibrary();
    LOGI("native bridge: %s", native_bridge.data());
    for (const char *name : {(const char *) "libhoudini.so", (const char *) native_bridge.data()}) {
        auto h = xdl_open(name, XDL_TRY_FORCE_LOAD);
        if (h && xdl_sym(h, "NativeBridgeItf", nullptr)) { nb = h; LOGI("using %s", name); break; }
    }
    if (nb) {
        LOGI("nb %p", nb);
        auto callbacks = (NativeBridgeCallbacks *) xdl_sym(nb, "NativeBridgeItf", nullptr);
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}

#endif