#pragma once
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

enum HTTP_REQUEST
{
	GET_HTTP_REQUEST = 0,
	POST_HTTP_REQUEST = 1,
};
enum HTTP_VERSION
{
	HTTP11_VERSION = 0,
};
enum HTTP_STATUS
{
	CONTINUE_HTTP_STATUS = 100,
	OK_HTTP_STATUS = 200,
	MULTIPLE_CHOICE_HTTP_STATUS = 300,
	BAD_REQUEST_HTTP_STATUS = 400,
	INTERNAL_SERVER_ERROR_HTTP_STATUS = 500,
};

struct HttpRequest;
struct HttpResponse;

char* serializeHttpRequest(
	uint8_t type,
	const char* uri,
	uint8_t version,
	size_t* size);

struct HttpRequest* deserializeHttpRequest(
	const char* data,
	size_t size);

void destroyHttpRequest(
	struct HttpRequest* request);

char* serializeHttpResponse(
	uint8_t version,
	uint16_t status,
	size_t* size);

struct HttpResponse* deserializeHttpResponse(
	const char* data,
	size_t size);

void destroyHttpResponse(
	struct HttpResponse* response);
