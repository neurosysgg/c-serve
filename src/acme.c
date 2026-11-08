/* ACME's shared parts (acme.h) */
#include "acme.h"

int cserve_acme_token_ok(const char *token, size_t n) {
  if (n == 0 || n > 128) {
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    char c = token[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_')) {
      return 0;
    }
  }
  return 1;
}
