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

// ---- decrypted global-metadata.dat save (Digimon-NC) ------------------------------------------
// The game decrypts global-metadata.dat into RAM during il2cpp_init. Scan our own readable mappings
// through /proc/self/mem (pread fails cleanly on unbacked pages, so nothing can fault), validate the
// IL2CPP header the same way Tools/il2cpp/carve_metadata.py does, and write each valid blob to
// <files>/metadata_<address>.bin for the offline carver to verify and pick.
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

static void dump_metadata(const char *game_data_dir) {
    FILE *maps = fopen("/proc/self/maps", "r");
    int mem = open("/proc/self/mem", O_RDONLY);
    if (!maps || mem < 0) {
        LOGE("metadata: cannot open maps/mem");
        if (maps) fclose(maps);
        if (mem >= 0) close(mem);
        return;
    }
    const size_t CHUNK = 16 * 1024 * 1024;
    std::vector<uint8_t> buf(CHUNK);
    std::vector<uint8_t> hdr(0x400);
    char line[1024];
    int written = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5] = {0};
        char path[512] = {0};
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %511[^\n]", &start, &end, perms, path) < 3) continue;
        if (perms[0] != 'r') continue;
        if (strncmp(path, "/dev/", 5) == 0 && strncmp(path, "/dev/ashmem", 11) != 0) continue;
        if (strcmp(path, "[vvar]") == 0 || strcmp(path, "[vsyscall]") == 0) continue;
        for (unsigned long base = start; base < end; base += CHUNK) {
            size_t want = std::min((unsigned long) CHUNK, end - base);
            ssize_t n = pread64(mem, buf.data(), want, (off64_t) base);
            if (n <= 12) continue;
            for (size_t i = 0; i + 12 <= (size_t) n; i += 4) {
                if (*(const uint32_t *) (buf.data() + i) != 0xFAB11BAFu) continue;
                unsigned long addr = base + i;
                ssize_t hn = pread64(mem, hdr.data(), hdr.size(), (off64_t) addr);
                if (hn <= 12) continue;
                uint32_t length = md_header_length(hdr.data(), (size_t) hn);
                if (!length) continue;
                std::vector<uint8_t> blob(length);
                if (pread64(mem, blob.data(), length, (off64_t) addr) != (ssize_t) length) {
                    LOGW("metadata: candidate at %lx (%u bytes) not fully readable", addr, length);
                    continue;
                }
                char out[PATH_MAX];
                snprintf(out, sizeof(out), "%s/files/metadata_%lx.bin", game_data_dir, addr);
                FILE *f = fopen(out, "wb");
                if (f) {
                    fwrite(blob.data(), 1, length, f);
                    fclose(f);
                    written++;
                    LOGI("metadata: v%d %u bytes at %lx -> %s", *(int32_t *) (hdr.data() + 4), length, addr, out);
                }
            }
        }
    }
    fclose(maps);
    close(mem);
    LOGI("metadata: %d candidate(s) written", written);
}
// -----------------------------------------------------------------------------------------------

void hack_start(const char *game_data_dir) {
    bool load = false;
    for (int i = 0; i < 10; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            dump_metadata(game_data_dir);
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