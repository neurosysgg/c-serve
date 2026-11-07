#ifndef CSERVE_FILE_H
#define CSERVE_FILE_H

#include "httpd.h"

/* A file on disk answered (phpanta's FileResponse): its bytes, all of
 * them or the one range a GET asks for, read as they're sent.
 *
 *   200  Content-Length: size              (no Range, one this doesn't
 *                                           read, or not a GET)
 *   206  Content-Length: n, Content-Range: bytes a-b/size
 *   416  Content-Length: 0, Content-Range: "bytes *" then "/size"
 *
 * each with Content-Type: type, then Accept-Ranges: bytes, Cache-Control:
 * no-store, private and the Content-Range, in that order: a caller adds
 * its own after. A HEAD is told what its GET would be, and reads nothing.
 * A Range is a GET's alone (Request::range()). */

/* path answered into rep: 0, or -1 when it can't be opened or isn't a
 * regular file (rep untouched: the caller's 404) or its headers won't
 * fit (rep a 500) */
int cserve_file_reply(const CSERVE_HTTPD_REQ *r, const char *path,
                      const char *type, CSERVE_HTTPD_REPLY *rep);

#endif
