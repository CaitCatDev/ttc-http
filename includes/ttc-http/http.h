#pragma once

#include <ttc-http/request.h>
#include <ttc-http/response.h>
#include <ttc-http/sockets.h>
#include <ttc-http/websockets.h>

#define TTC_HTTP_VER_MAJ 0
#define TTC_HTTP_VER_MIN 7
#define TTC_HTTP_VER_VENDOR "ttc"

#define TTC_HTTP_VER_STR TTC_HTTP_VER_MAJ #"." TTC_HTTP_VER_MIN #"_" TTC_HTTP_VER_VENDOR

#define TTC_HTTP_FN_FAILED -1
#define TTC_HTTP_FN_SUCCESS 0
