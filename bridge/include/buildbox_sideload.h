#ifndef BUILDBOX_SIDELOAD_H
#define BUILDBOX_SIDELOAD_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// `(ctx, params_json, out_buf, out_cap) -> bytes_written | -1 cancelled | -2 buffer too small`
typedef intptr_t (*bbs_two_factor_cb)(void *ctx, const char *params_json, char *out_buf, size_t out_cap);

/// `(ctx, progress_0_to_1)`
typedef void (*bbs_progress_cb)(void *ctx, float progress);

int32_t bbs_init(void);
char *bbs_version(void);
void bbs_string_free(char *s);

char *bbs_login(const char *email,
                const char *password,
                const char *storage_dir,
                const char *machine_name,
                bbs_two_factor_cb two_factor_cb,
                void *ctx);

char *bbs_list_teams(uint64_t handle);

char *bbs_export_identity(uint64_t handle,
                          const char *bundle_id,
                          const char *app_name,
                          const char *device_udid,
                          const char *device_name,
                          const char *out_dir,
                          const char *p12_password);

char *bbs_sign_ipa(uint64_t handle,
                   const char *ipa_path,
                   const char *device_udid,
                   const char *device_name,
                   bool increased_memory_limit,
                   bbs_progress_cb progress_cb,
                   void *ctx);

int32_t bbs_logout(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif

