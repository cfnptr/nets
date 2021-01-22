#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/* HTTP request type */
enum HTTP_REQUEST
{
	GET_HTTP_REQUEST = 0,
	POST_HTTP_REQUEST = 1,
};

/* HTTP protocol version */
enum HTTP_VERSION
{
	HTTP_10_VERSION = 0,
	HTTP_11_VERSION = 1,
};

/* HTTP status code */
enum HTTP_STATUS
{
	CONTINUE_HTTP_STATUS = 100,
	OK_HTTP_STATUS = 200,
	MULTIPLE_CHOICE_HTTP_STATUS = 300,
	BAD_REQUEST_HTTP_STATUS = 400,
	UNAUTHORIZED_HTTP_STATUS = 401,
	FORBIDDEN_HTTP_STATUS = 403,
	NOT_FOUND_HTTP_STATUS = 404,
	INTERNAL_SERVER_ERROR_HTTP_STATUS = 500,
	NOT_IMPLEMENTED_HTTP_STATUS = 501,
};

/* HTTP body content type */
enum HTTP_CONTENT
{
	NONE_HTTP_CONTENT = 0,
	TEXT_HTML_HTTP_CONTENT = 1,
};

/* HTTP request instance */
struct HttpRequest;
/* HTTP response instance */
struct HttpResponse;

/*
 * Serializes HTTP request to the data.
 * Returns serialized request on success, otherwise NULL.
 *
 * type - HTTP request type.
 * uri - pointer to the valid HTTP URI string.
 * version - HTTP protocol version.
 */
char* serializeHttpRequest(
	uint8_t type,
	const char* uri,
	uint8_t version,
	size_t* size);

/*
 * Deserializes HTTP request from the data.
 * Return HTTP request on success, otherwise NULL.
 *
 * data - pointer to the valid serialized data.
 * size - serialized data size.
 */
struct HttpRequest* deserializeHttpRequest(
	const char* data,
	size_t size);

/*
 * Destroys specified HTTP request.
 * request - pointer to the HTTP request or NULL.
 */
void destroyHttpRequest(
	struct HttpRequest* request);

/*
 * Returns HTTP request type.
 * request - pointer to the valid HTTP request.
 */
uint8_t getHttpRequestType(
	const struct HttpRequest* request);

/*
 * Returns HTTP request URI string.
 * request - pointer to the valid HTTP request.
 */
const char* getHttpRequestUri(
	const struct HttpRequest* request);

/*
 * Returns HTTP request protocol version.
 * request - pointer to the valid HTTP request.
 */
uint8_t getHttpRequestVersion(
	const struct HttpRequest* request);

/*
 * Serializes HTTP response to the data.
 * Returns serialized response on success, otherwise null.
 *
 * version - HTTP protocol version.
 * status - HTTP response status code.
 * contentType - HTTP response content type.
 * content - HTTP response body data.
 * contentLength - HTTP response content length.
 * size - pointer to the valid data size.
 */
char* serializeHttpResponse(
	uint8_t version,
	uint16_t status,
	uint8_t contentType,
	const char* content,
	size_t contentLength,
	size_t* size);

/*
 * Deserializes HTTP response from the data.
 * Return HTTP response on success, otherwise NULL.
 *
 * data - pointer to the valid serialized data.
 * size - serialized data size.
 */
struct HttpResponse* deserializeHttpResponse(
	const char* data,
	size_t size);

/*
 * Destroys specified HTTP response.
 * request - pointer to the HTTP response or NULL.
 */
void destroyHttpResponse(
	struct HttpResponse* response);

/*
 * Returns HTTP response protocol version.
 * response - pointer to the valid HTTP response.
 */
uint8_t getHttpResponseVersion(
	struct HttpResponse* response);

/*
 * Returns HTTP response status code.
 * response - pointer to the valid HTTP response.
 */
uint16_t getHttpResponseStatus(
	struct HttpResponse* response);

/*
 * Returns HTTP response content type.
 * response - pointer to the valid HTTP response.
 */
uint8_t getHttpResponseContentType(
	struct HttpResponse* response);

/*
 * Returns HTTP response content.
 * response - pointer to the valid HTTP response.
 */
const char* getHttpResponseContent(
	struct HttpResponse* response);

/*
 * Returns HTTP response content length.
 * response - pointer to the valid HTTP response.
 */
size_t getHttpResponseContentLength(
	struct HttpResponse* response);
