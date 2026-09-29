/* The net plugin's vtable (plugin.h): HTTP(S) with our own small client
 * (net.h), so mbedtls is only mapped by what talks to the net -- the
 * weather widget's fetch child, not its zone. Kept apart from net.c so
 * the tests can link that without it. */

#include "http.h"
#include "net.h"

#include "base/plugin.h"

static int net_init(const CTUI_WM_CONFIG *cfg) {
  (void)cfg;
  return 0;
}

static const CTUI_WM_NET_OPS OPS = {
    .http = ctui_wm_net_http,
    .header = ctui_wm_http_reply_header,
    .http_stream = ctui_wm_net_http_stream,
};

const CTUI_WM_PLUGIN ctui_wm_plugin = {
    CTUI_WM_PLUGIN_HEADER("net"),
    .init = net_init,
    .net = &OPS,
};
