#pragma once
#include "mpnw/socket.h"

struct ClientSocket;

typedef bool(*ClientReceiveHandler)(
	size_t count,
	struct Socket* socket,
	const char* receiveBuffer);

