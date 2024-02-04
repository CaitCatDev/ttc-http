#pragma once


#define TTC_HTTP_METHOD_GET "GET"
#define TTC_HTTP_METHOD_POST "POST"
#define TTC_HTTP_METHOD_DELETE "DELETE"
#define TTC_HTTP_METHOD_HEAD "HEAD"
#define TTC_HTTP_METHOD_PUT "PUT"
#define TTC_HTTP_METHOD_CONNECT "CONNECT"
#define TTC_HTTP_METHOD_OPTIONS "OPTIONS"
#define TTC_HTTP_METHOD_TRACE "TRACE"
#define TTC_HTTP_METHOD_PATCH "PATCH"

#define HTTP_VER_09 ""
#define HTTP_VER_10 "HTTP/1.0"
#define HTTP_VER_11 "HTTP/1.1"
#define HTTP_VER_2 "HTTP/2"
#define HTTP_VER_3 "HTTP/3"
/** @file request.h
 * Request functions follow this format
 * ttc_http_request_set_* sets data i.e. overwrites previous data
 * ttc_http_request_add_* adds data to the end of previous data
 * all functions are safe to be called with NULL values
 *
 * requests have a dirty bit and you can thus call
 * ttc_http_request_build whenever you need to be sure
 * the request is rebuilt and so long as the dirty
 * bit isn't set it won't be rebuilt.
 *
 * and ttc_http_socket_send_request will build the request
 * on send you do not need to call this function
 * but we keep it for historical/backwards
 * compat reasons.
 */

typedef struct ttc_http_request ttc_http_request_t;

/** @brief Create a new http request
 *  @return NULL on error pointer on success
 */
ttc_http_request_t *ttc_http_new_request();

/** @brief set the method of HTTP request
 *  @param request ptr to the request whose method to set
 *	@param method string
 *	@return -1 on error 0 on success
 */
int ttc_http_request_set_method(ttc_http_request_t *request, const char *method);

/** @brief set the path of HTTP request
 *  @param request ptr to the request whose path to set
 *	@param path string
 *	@return -1 on error 0 on success
 */
int ttc_http_request_set_path(ttc_http_request_t *request, const char *path);

/** @brief set the version of HTTP request
 *  @param request ptr to the request whose path to set
 *	@param version string
 *	@return -1 on error 0 on success
 */
int ttc_http_request_set_http_version(ttc_http_request_t *request, const char *http_ver);

/** @brief add a header to the request
 *  @param request the request to add header to
 *	@param name the name of the header e.g Host,Accept,Connection
 *  @param value the value you want this header entry to have
 */
int ttc_http_request_add_header(ttc_http_request_t *request, const char *name, const char *value);

/** @brief delete a header from the request
 *  @param request a pointer to request
 *  @param name the name of the header you want to delete
 */
void ttc_http_request_del_header(ttc_http_request_t *request, const char *name);

/** @brief set the data for a request
 *  NOTE any headers needed by this data is something you need to set
 *  @param request the request to attach data to
 *  @param the data
 */
int ttc_http_request_set_data(ttc_http_request_t *request, const char *data);

/** @brief build a request into something that can be sent
 *  Build the request into something that can be sent with ttc_socket_send_request
 *  This is no longer needed as ttc_socket_send_request will build the request for you
 *  but you are still free to use it.
 *  @param request to be built
 */
int ttc_http_request_build(ttc_http_request_t *request);

/** @brief free a request and all data linked to it
 * @param request to free
 */
void ttc_http_request_free(ttc_http_request_t *request);
