// Copyright 2020-2025 Nikita Fediuchin. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/***********************************************************************************************************************
 * @file
 * @brief Common network stream message functions.
 */

#pragma once
#include "nets/defines.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Stream message structure.
 */
typedef struct StreamMessage
{
	uint8_t* iter;
	uint8_t* end;
} StreamMessage;

/**
 * @brief Creates a new stream message.
 *
 * @param[in,out] buffer message data buffer
 * @param[in,out] buffer message buffer in bytes
 * @param messageSize message size in bytes
 * @param lengthSize message header lenght size in bytes
 */
inline static StreamMessage createStreamMessage(uint8_t* buffer, 
	size_t bufferSize, size_t messageSize, uint8_t lengthSize)
{
	assert(buffer);
	assert(messageSize + lengthSize <= bufferSize);

	assert((lengthSize == sizeof(uint8_t) && messageSize <= UINT8_MAX) ||
		(lengthSize == sizeof(uint16_t) && messageSize <= UINT16_MAX) ||
		(lengthSize == sizeof(uint32_t) && messageSize <= UINT32_MAX) ||
		(lengthSize == sizeof(uint64_t) && messageSize <= UINT64_MAX));

	StreamMessage streamMessage;
	if (lengthSize == sizeof(uint8_t))
	{
		*buffer = (uint8_t)messageSize;
		streamMessage.iter = buffer + sizeof(uint8_t);
	}
	else if (lengthSize == sizeof(uint16_t))
	{
		*((uint16_t*)buffer) = hostToLE16(messageSize);
		streamMessage.iter = buffer + sizeof(uint16_t);
	}
	else if (lengthSize == sizeof(uint32_t))
	{
		*((uint32_t*)buffer) = hostToLE32(messageSize);
		streamMessage.iter = buffer + sizeof(uint32_t);
	}
	else if (lengthSize == sizeof(uint64_t))
	{
		*((uint64_t*)buffer) = hostToLE64(messageSize);
		streamMessage.iter = buffer + sizeof(uint64_t);
	}
	else abort();

	streamMessage.end = streamMessage.iter + messageSize;
	return streamMessage;
}

/**
 * @brief Returns true if stream message is not empty and complete, otherwise false.
 * @param streamMessage target stream message to validate
 */
inline static bool isStreamMessageComplete(StreamMessage streamMessage)
{
	return streamMessage.iter && streamMessage.iter == streamMessage.end;
}
/**
 * @brief Returns stream message byte count left to read or write.
 * @param streamMessage target stream message
 */
inline static size_t getStreamMessageLeft(StreamMessage streamMessage)
{
	return streamMessage.end - streamMessage.iter;
}

/***********************************************************************************************************************
 * @brief Reads data from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] data pointer to the message data
 * @param count message byte count to read
 */
inline static bool readStreamMessage(StreamMessage* streamMessage, const void** data, size_t count)
{
	assert(streamMessage);
	assert(data);
	if (streamMessage->iter + count > streamMessage->end)
		return true;
	*data = streamMessage->iter;
	streamMessage->iter += count;
	return false;
}
/**
 * @brief Writes data to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[in] data message data to write
 * @param count message byte count to write
 */
inline static bool writeStreamMessage(StreamMessage* streamMessage, const void* data, size_t count)
{
	assert(streamMessage);
	assert(data);
	if (streamMessage->iter + count > streamMessage->end)
		return true;
	memcpy(streamMessage->iter, data, count * sizeof(uint8_t));
	streamMessage->iter += count;
	return false;
}

/***********************************************************************************************************************
 * @brief Reads 8-bit unsigned integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the unsigned integer value
 */
inline static bool readStreamMessageUint8(StreamMessage* streamMessage, uint8_t* value)
{
	assert(streamMessage);
	assert(value);
	if (streamMessage->iter + sizeof(uint8_t) > streamMessage->end)
		return true;
	*value = *streamMessage->iter;
	streamMessage->iter += sizeof(uint8_t);
	return false;
}
/**
 * @brief Reads 16-bit unsigned integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the unsigned integer value
 */
inline static bool readStreamMessageUint16(StreamMessage* streamMessage, uint16_t* value)
{
	assert(streamMessage);
	assert(value);
	if (streamMessage->iter + sizeof(uint16_t) > streamMessage->end)
		return true;
	*value = leToHost16(*((const uint16_t*)streamMessage->iter));
	streamMessage->iter += sizeof(uint16_t);
	return false;
}
/**
 * @brief Reads 32-bit unsigned integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the unsigned integer value
 */
inline static bool readStreamMessageUint32(StreamMessage* streamMessage, uint32_t* value)
{
	assert(streamMessage);
	assert(value);
	if (streamMessage->iter + sizeof(uint32_t) > streamMessage->end)
		return true;
	*value = leToHost32(*((const uint32_t*)streamMessage->iter));
	streamMessage->iter += sizeof(uint32_t);
	return false;
}
/**
 * @brief Reads 64-bit unsigned integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the unsigned integer value
 */
inline static bool readStreamMessageUint64(StreamMessage* streamMessage, uint64_t* value)
{
	assert(streamMessage);
	assert(value);
	if (streamMessage->iter + sizeof(uint64_t) > streamMessage->end)
		return true;
	*value = leToHost64(*((const uint64_t*)streamMessage->iter));
	streamMessage->iter += sizeof(uint64_t);
	return false;
}

/***********************************************************************************************************************
 * @brief Writes 8-bit unsigned integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value unsigned integer value to write
 */
inline static bool writeStreamMessageUint8(StreamMessage* streamMessage, uint8_t value)
{
	assert(streamMessage);
	if (streamMessage->iter + sizeof(uint8_t) > streamMessage->end)
		return true;
	*streamMessage->iter = value;
	streamMessage->iter += sizeof(uint8_t);
	return false;
}
/**
 * @brief Writes 16-bit unsigned integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value unsigned integer value to write
 */
inline static bool writeStreamMessageUint16(StreamMessage* streamMessage, uint16_t value)
{
	assert(streamMessage);
	if (streamMessage->iter + sizeof(uint16_t) > streamMessage->end)
		return true;
	*((uint16_t*)streamMessage->iter) = hostToLE16(value);
	streamMessage->iter += sizeof(uint16_t);
	return false;
}
/**
 * @brief Writes 32-bit unsigned integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value unsigned integer value to write
 */
inline static bool writeStreamMessageUint32(StreamMessage* streamMessage, uint32_t value)
{
	assert(streamMessage);
	if (streamMessage->iter + sizeof(uint32_t) > streamMessage->end)
		return true;
	*((uint32_t*)streamMessage->iter) = hostToLE32(value);
	streamMessage->iter += sizeof(uint32_t);
	return false;
}
/**
 * @brief Writes 64-bit unsigned integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value unsigned integer value to write
 */
inline static bool writeStreamMessageUint64(StreamMessage* streamMessage, uint64_t value)
{
	assert(streamMessage);
	if (streamMessage->iter + sizeof(uint64_t) > streamMessage->end)
		return true;
	*((uint64_t*)streamMessage->iter) = hostToLE64(value);
	streamMessage->iter += sizeof(uint64_t);
	return false;
}

/***********************************************************************************************************************
 * @brief Reads 8-bit signed integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the signed integer value
 */
inline static bool readStreamMessageInt8(StreamMessage* streamMessage, int8_t* value)
{
	return readStreamMessageUint8(streamMessage, (uint8_t*)value);
}
/**
 * @brief Reads 16-bit signed integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the signed integer value
 */
inline static bool readStreamMessageInt16(StreamMessage* streamMessage, int16_t* value)
{
	return readStreamMessageUint16(streamMessage, (uint16_t*)value);
}
/**
 * @brief Reads 32-bit signed integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the signed integer value
 */
inline static bool readStreamMessageInt32(StreamMessage* streamMessage, int32_t* value)
{
	return readStreamMessageUint32(streamMessage, (uint32_t*)value);
}
/**
 * @brief Reads 64-bit signed integer value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the signed integer value
 */
inline static bool readStreamMessageInt64(StreamMessage* streamMessage, int64_t* value)
{
	return readStreamMessageUint64(streamMessage, (uint64_t*)value);
}

/**
 * @brief Writes 8-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value signed integer value to write
 */
inline static bool writeStreamMessageInt8(StreamMessage* streamMessage, int8_t value)
{
	return writeStreamMessageUint8(streamMessage, *((uint8_t*)&value));
}
/**
 * @brief Writes 16-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value signed integer value to write
 */
inline static bool writeStreamMessageInt16(StreamMessage* streamMessage, int16_t value)
{
	return writeStreamMessageUint16(streamMessage, *((uint16_t*)&value));
}
/**
 * @brief Writes 32-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value signed integer value to write
 */
inline static bool writeStreamMessageInt32(StreamMessage* streamMessage, int32_t value)
{
	return writeStreamMessageUint32(streamMessage, *((uint32_t*)&value));
}
/**
 * @brief Writes 64-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value signed integer value to write
 */
inline static bool writeStreamMessageInt64(StreamMessage* streamMessage, int64_t value)
{
	return writeStreamMessageUint64(streamMessage, *((uint64_t*)&value));
}

/***********************************************************************************************************************
 * @brief Reads 32-bit floating point value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the floating point value
 */
inline static bool readStreamMessageFloat32(StreamMessage* streamMessage, float* value)
{
	return readStreamMessageUint32(streamMessage, (uint32_t*)value);
}
/**
 * @brief Reads 64-bit floating point value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the floating point value
 */
inline static bool readStreamMessageFloat64(StreamMessage* streamMessage, double* value)
{
	return readStreamMessageUint64(streamMessage, (uint64_t*)value);
}

/**
 * @brief Writes 32-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value floating point value to write
 */
inline static bool writeStreamMessageFloat32(StreamMessage* streamMessage, float value)
{
	return writeStreamMessageUint32(streamMessage, *((uint32_t*)&value));
}
/**
 * @brief Writes 64-bit signed integer value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value floating point value to write
 */
inline static bool writeStreamMessageFloat64(StreamMessage* streamMessage, double value)
{
	return writeStreamMessageUint64(streamMessage, *((uint64_t*)&value));
}

/***********************************************************************************************************************
 * @brief Reads data from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] data pointer to the message data
 * @param[out] dataSize pointer to the data size in bytes
 * @param lengthSize length of the data size in bytes
 */
inline static bool readStreamMessageData(StreamMessage* streamMessage, 
	const void** data, size_t* dataSize, uint8_t lengthSize)
{
	assert(data);
	assert(dataSize);

	assert(lengthSize == sizeof(uint8_t) || lengthSize == sizeof(uint16_t) ||
		lengthSize == sizeof(uint32_t) || lengthSize == sizeof(uint64_t));

	size_t length;
	if (lengthSize == sizeof(uint8_t))
	{
		uint8_t size;
		if (readStreamMessageUint8(streamMessage, &size))
			return true;
		length = size;
	}
	else if (lengthSize == sizeof(uint16_t))
	{
		uint16_t size;
		if (readStreamMessageUint16(streamMessage, &size))
			return true;
		length = size;
	}
	else if (lengthSize == sizeof(uint32_t))
	{
		uint32_t size;
		if (readStreamMessageUint32(streamMessage, &size))
			return true;
		length = size;
	}
	else if (lengthSize == sizeof(uint64_t))
	{
		uint64_t size;
		if (readStreamMessageUint64(streamMessage, &size))
			return true;
		length = size;
	}
	else abort();

	if (readStreamMessage(streamMessage, data, length))
		return true;
	*dataSize = length;
	return false;
}
/**
 * @brief Writes data to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[in] data message data to write
 * @param dataSize data size in bytes
 * @param lengthSize length of the data size in bytes
 */
inline static bool writeStreamMessageData(StreamMessage* streamMessage, 
	const void* data, size_t dataSize, uint8_t lengthSize)
{
	assert(data);
	assert(
		(lengthSize == sizeof(uint8_t) && dataSize <= UINT8_MAX) ||
		(lengthSize == sizeof(uint16_t) && dataSize <= UINT16_MAX) ||
		(lengthSize == sizeof(uint32_t) && dataSize <= UINT32_MAX) ||
		(lengthSize == sizeof(uint64_t) && dataSize <= UINT64_MAX));

	if (lengthSize == sizeof(uint8_t))
	{
		if (writeStreamMessageUint8(streamMessage, (uint8_t)dataSize))
			return true;
	}
	else if (lengthSize == sizeof(uint16_t))
	{
		if (writeStreamMessageUint16(streamMessage, (uint16_t)dataSize))
			return true;
	}
	else if (lengthSize == sizeof(uint32_t))
	{
		if (writeStreamMessageUint32(streamMessage, (uint32_t)dataSize))
			return true;
	}
	else if (lengthSize == sizeof(uint64_t))
	{
		if (writeStreamMessageUint64(streamMessage, (uint64_t)dataSize))
			return true;
	}
	else abort();

	return writeStreamMessage(streamMessage, data, dataSize);
}

/**
 * @brief Writes boolean value to the stream message and advances offset.
 * @return True if no more space to write data, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param value boolean value to write
 */
inline static bool writeStreamMessageBool(StreamMessage* streamMessage, bool value)
{
	return writeStreamMessageUint8(streamMessage, value ? 1 : 0);
}
/**
 * @brief Reads boolean value from the stream message and advances offset.
 * @return True if no more data to read, otherwise false.
 *
 * @param[in,out] streamMessage target stream message
 * @param[out] value pointer to the signed integer value
 */
inline static bool readStreamMessageBool(StreamMessage* streamMessage, bool* value)
{
	uint8_t data;
	if (readStreamMessageUint8(streamMessage, &data))
		return true;
	*value = data ? true : false;
	return false;
}

/***********************************************************************************************************************
 * @brief Splits received stream data to the messages.
 * @return The receive operation result code.
 *
 * @param[in] receiveBuffer received message buffer
 * @param byteCount message received byte count
 * @param[in,out] messageBuffer intermediate message buffer
 * @param messageBufferSize intermediate message buffer size in bytes (including messageLengthSize)
 * @param[in,out] messageByteCount pointer to the message buffer byte count
 * @param messageLengthSize message length header size in bytes (1, 2, 4 or 8)
 * @param[in] receiveFunction pointer to the receive function
 * @param[in] functionHandle receive function handle or NULL
 */
inline static int handleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, 
	uint8_t* messageBuffer, size_t messageBufferSize, size_t* messageByteCount, 
	uint8_t messageLengthSize, int(*receiveFunction)(StreamMessage, void*), void* functionHandle)
{
	assert(receiveBuffer);
	assert(messageBuffer);
	assert(messageBufferSize > 0);
	assert(messageByteCount);

	assert(messageLengthSize == sizeof(uint8_t) || messageLengthSize == sizeof(uint16_t) ||
		messageLengthSize == sizeof(uint32_t) || messageLengthSize == sizeof(uint64_t));
	assert(messageBufferSize >= messageLengthSize);

	if (byteCount == 0) // Check instead of assert for safety
		return CONNECTION_IS_CLOSED_NETS_RESULT;

	StreamMessage streamMessage;
	size_t _messageByteCount = *messageByteCount;
	size_t pointer = 0;
	
	if (_messageByteCount > 0) // Handle received data with buffered data
	{
		if (_messageByteCount < messageLengthSize) // Message buffer has not full size
		{
			size_t messageSizePart = (size_t)messageLengthSize - _messageByteCount;
			if (messageSizePart > byteCount) // Received not full message size
			{
				// Store part of the received message size
				memcpy(messageBuffer + _messageByteCount, receiveBuffer, byteCount * sizeof(uint8_t));
				*messageByteCount += byteCount;
				return SUCCESS_NETS_RESULT;
			}

			// Copy remaining message size part
			memcpy(messageBuffer + _messageByteCount, receiveBuffer, messageSizePart * sizeof(uint8_t));
			pointer += messageSizePart;
			_messageByteCount += messageSizePart;
		}

		size_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
			messageSize = *((const uint8_t*)messageBuffer);
		else if (messageLengthSize == sizeof(uint16_t))
			messageSize = leToHost16(*(const uint16_t*)(messageBuffer));
		else if (messageLengthSize == sizeof(uint32_t))
			messageSize = leToHost32(*(const uint32_t*)(messageBuffer));
		else if (messageLengthSize == sizeof(uint64_t))
			messageSize = leToHost64(*(const uint64_t*)(messageBuffer));
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return BAD_DATA_NETS_RESULT; // Received message is bigger than buffer

		size_t neededPartSize = messageSize - (_messageByteCount - messageLengthSize);
		if (neededPartSize > byteCount - pointer) 
		{
			size_t messagePartSize = byteCount - pointer;
			memcpy(messageBuffer + _messageByteCount, receiveBuffer + pointer, messagePartSize * sizeof(uint8_t));
			*messageByteCount = _messageByteCount + messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		memcpy(messageBuffer + _messageByteCount, receiveBuffer + pointer, neededPartSize * sizeof(uint8_t));
		streamMessage.iter = messageBuffer + messageLengthSize;
		streamMessage.end = streamMessage.iter + messageSize;
		
		int result = receiveFunction(streamMessage, functionHandle);
		if (result != SUCCESS_NETS_RESULT)
			return result;

		*messageByteCount = 0;
		pointer += neededPartSize;
	}

	while (pointer < byteCount) // Continue until all received data handled
	{
		if (messageLengthSize > byteCount - pointer)
		{
			size_t messageSizePart = byteCount - pointer;
			memcpy(messageBuffer, receiveBuffer + pointer, messageSizePart * sizeof(uint8_t));
			*messageByteCount += messageSizePart;
			return SUCCESS_NETS_RESULT; // Received not full message size
		}

		size_t messageSize; // Decode received message size
		if (messageLengthSize == sizeof(uint8_t))
			messageSize = *((const uint8_t*)receiveBuffer + pointer);
		else if (messageLengthSize == sizeof(uint16_t))
			messageSize = leToHost16(*(const uint16_t*)(receiveBuffer + pointer));
		else if (messageLengthSize == sizeof(uint32_t))
			messageSize = leToHost32(*(const uint32_t*)(receiveBuffer + pointer));
		else if (messageLengthSize == sizeof(uint64_t))
			messageSize = leToHost64(*(const uint64_t*)(receiveBuffer + pointer));
		else abort();

		if (messageSize > messageBufferSize - messageLengthSize)
			return BAD_DATA_NETS_RESULT; // Received message is bigger than buffer

		if (messageSize > (byteCount - pointer) - messageLengthSize)
		{
			size_t messagePartSize = byteCount - pointer;
			memcpy(messageBuffer, receiveBuffer + pointer, messagePartSize * sizeof(uint8_t));
			*messageByteCount += messagePartSize;
			return SUCCESS_NETS_RESULT; // Received not full message
		}

		streamMessage.iter = (uint8_t*)receiveBuffer + (pointer + messageLengthSize);
		streamMessage.end = streamMessage.iter + messageSize;

		int result = receiveFunction(streamMessage, functionHandle);
		if (result != SUCCESS_NETS_RESULT)
			return result;
		pointer += messageLengthSize + messageSize;
	}

	return SUCCESS_NETS_RESULT;
}

// For library symbols
int sHandleStreamMessage(const uint8_t* receiveBuffer, size_t byteCount, uint8_t* messageBuffer, 
	size_t messageBufferSize, size_t* messageByteCount, uint8_t messageLengthSize, 
	int(*receiveFunction)(StreamMessage, void*), void* functionHandle);