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

struct HttpRequest
{
	uint8_t type;
	uint8_t version;
	char* uri;
};
struct HttpResponse
{
	uint8_t version;
	uint8_t status;
};

inline static bool serializeHttpRequest(
	struct HttpRequest request,
	char** _data,
	size_t* _size)
{
	assert(_data != NULL);
	assert(_size != NULL);

	const char* type;
	size_t typeSize;

	if (request.type == GET_HTTP_REQUEST)
	{
		type = "GET ";
		typeSize = 4;
	}
	else if (request.type == POST_HTTP_REQUEST)
	{
		type = "POST ";
		typeSize = 5;
	}
	else
	{
		return false;
	}

	const char* version;
	size_t versionSize;

	if (request.version == HTTP11_VERSION)
	{
		version = " HTTP/1.1\r\n";
		versionSize = 11;
	}
	else
	{
		return false;
	}

	size_t uriSize =
		strlen(request.uri);

	size_t size =
		typeSize +
		uriSize +
		versionSize + 2;

	char* data = malloc(
		size * sizeof(char));

	if (data == NULL)
		return false;

	size_t index = 0;

	memcpy(
		data + index,
		type,
		typeSize * sizeof(char));
	index += typeSize;

	memcpy(
		data + index,
		request.uri,
		typeSize * sizeof(char));
	index += uriSize;

	memcpy(
		data + index,
		version,
		typeSize * sizeof(char));
	index += versionSize;

	memcpy(
		data + index,
		"\r\n",
		2 * sizeof(char));

	*_data = data;
	*_size = size;
	return true;
}

inline static bool deserializeHttpRequest(
	const char* data,
	size_t size,
	struct HttpRequest* _request)
{
	assert(data != NULL);
	assert(size != 0);
	assert(_request != NULL);

	if (size <)

	struct HttpRequest request;

	for (size_t i = 0; i < size; i++)
	{
		if (data[i] == ' ')
		{
			if (memcmp(data, "GET", 3) == 0)
			{
				request.type = GET_HTTP_REQUEST;
				goto URI_JUMP;
			}
			else if (memcmp(data, "POST", 4) == 0)
			{
				request.type = POST_HTTP_REQUEST;
				goto URI_JUMP;
			}
		}
	}

	return false;

URI_JUMP:
}