// Copyright 2020-2026 Nikita Fediuchin. All rights reserved.
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
 * @brief Network stream message functions.
 * @details See the @ref stream-message.h
 */

#pragma once
#include <array>
#include <vector>
#include <string>
#include <string_view>

extern "C"
{
#include "nets/stream-message.h"
}

namespace nets
{

/**
 * @brief Network stream message container. (TCP)
 * @details See the @ref stream-message.h
 */
class StreamMessage : public ::StreamMessage
{
protected:
	using ::StreamMessage::end;
public:
	/**
	 * @brief Maximum size of the stream message length in bytes.
	 */
	static constexpr uint8_t maxLengthSize = STREAM_MESSAGE_MAX_LENGTH_SIZE;
	/**
	 * @brief Safe maximum UDP datagram size in bytes. (Includes IP and VPN overhead)
	 */
	static constexpr uint16_t maxDatagramSize = MAX_DATAGRAM_MESSAGE_SIZE;

	/**
	 * @brief Creates a new empty stream message.
	 */
	StreamMessage() noexcept { iter = nullptr; end = nullptr; }
	/**
	 * @brief Creates a new stream message. (TCP)
	 * @param streamMessage target stream message data
	 */
	StreamMessage(::StreamMessage streamMessage) noexcept
	{
		iter = streamMessage.iter;
		end = streamMessage.end;
	}

	/**
	 * @brief Returns stream message end pointer.
	 */
	const uint8_t* getEnd() const noexcept { return end; }

	/**
	 * @brief Returns true if stream message is not empty and complete, otherwise false.
	 * @details See the @ref isStreamMessageComplete().
	 */
	bool isComplete() const noexcept { return isStreamMessageComplete(*this); }
	/**
	 * @brief Returns stream message byte count left to read or write.
	 * @details See the @ref getStreamMessageLeft().
	 */
	size_t getLeft() const noexcept { return getStreamMessageLeft(*this); }

	/**
	 * @brief Reads data from the stream message and advances offset.
	 * @details See the @ref readStreamMessage().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @param[out] data reference to the message data
	 * @param count message byte count to read
	 */
	bool read(const void*& data, size_t count) noexcept { return readStreamMessage(this, &data, count); }

	/*******************************************************************************************************************
	 * @brief Reads 8-bit unsigned integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageUint8().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the unsigned integer value
	 */
	bool read(uint8_t& value) noexcept { return readStreamMessageUint8(this, &value); }
	/**
	 * @brief Reads 16-bit unsigned integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageUint16().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the unsigned integer value
	 */
	bool read(uint16_t& value) noexcept { return readStreamMessageUint16(this, &value); }
	/**
	 * @brief Reads 32-bit unsigned integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageUint32().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the unsigned integer value
	 */
	bool read(uint32_t& value) noexcept { return readStreamMessageUint32(this, &value); }
	/**
	 * @brief Reads 64-bit unsigned integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageUint64().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the unsigned integer value
	 */
	bool read(uint64_t& value) noexcept { return readStreamMessageUint64(this, &value); }

	/**
	 * @brief Reads 8-bit signed integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageInt8().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the signed integer value
	 */
	bool read(int8_t& value) noexcept { return readStreamMessageInt8(this, &value); }
	/**
	 * @brief Reads 16-bit signed integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageInt16().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the signed integer value
	 */
	bool read(int16_t& value) noexcept { return readStreamMessageInt16(this, &value); }
	/**
	 * @brief Reads 32-bit signed integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageInt32().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the signed integer value
	 */
	bool read(int32_t& value) noexcept { return readStreamMessageInt32(this, &value); }
	/**
	 * @brief Reads 64-bit signed integer value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageInt64().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the signed integer value
	 */
	bool read(int64_t& value) noexcept { return readStreamMessageInt64(this, &value); }

	/*******************************************************************************************************************
	 * @brief Reads 32-bit floating point value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageFloat32().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the floating point value
	 */
	bool read(float& value) noexcept { return readStreamMessageFloat32(this, &value); }
	/**
	 * @brief Reads 64-bit floating point value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageFloat64().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the floating point value
	 */
	bool read(double& value) noexcept { return readStreamMessageFloat64(this, &value); }

	/**
	 * @brief Reads string from the stream message and advances offset.
	 * @details See the @ref readStreamMessageData().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @param[out] value reference to the message string
	 * @param lengthSize length of the string size in bytes
	 */
	bool read(std::string_view& value, uint8_t lengthSize) noexcept
	{
		const void* data; size_t length;
		if (readStreamMessageData(this, &data, &length, lengthSize))
			return true;
		value = std::string_view((const char*)data, length);
		return false;
	}
	/**
	 * @brief Reads string from the stream message and advances offset.
	 * @details See the @ref readStreamMessageData().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @param[out] value reference to the message string
	 * @param lengthSize length of the string size in bytes
	 */
	bool read(std::string& value, uint8_t lengthSize) noexcept
	{
		const void* data; size_t length;
		if (readStreamMessageData(this, &data, &length, lengthSize))
			return true;
		value = std::string((const char*)data, length);
		return false;
	}

	/**
	 * @brief Reads boolean value from the stream message and advances offset.
	 * @details See the @ref readStreamMessageBool().
	 * @return True if no more data to read, otherwise false.
	 * @param[out] value reference to the boolean value
	 */
	bool read(bool& value) noexcept { return readStreamMessageBool(this, &value); }

	/**
	 * @brief Reads data from the stream message and advances offset.
	 * @details See the @ref readStreamMessageData().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @param[out] data reference to the message data
	 * @param[out] dataSize reference to the data size in bytes
	 * @param lengthSize length of the data size in bytes
	 */
	bool read(const void*& data, size_t& dataSize, uint8_t lengthSize) noexcept
	{
		return readStreamMessageData(this, &data, &dataSize, lengthSize);
	}
	/**
	 * @brief Reads vector data from the stream message and advances offset.
	 * @details See the @ref readStreamMessageData().
	 * @return True if no more data to read, otherwise false.
	 *
	 * @tparam T type of the vector data
	 * @param[out] data reference to the message data vector
	 * @param lengthSize length of the data size in bytes
	 */
	template<class T>
	bool read(std::vector<T>& data, uint8_t lengthSize) noexcept
	{
		const void* messageData; size_t size;
		if (readStreamMessageData(this, &messageData, &size, lengthSize))
			return true;
		data.resize(size / sizeof(T));
		memcpy(data.data(), messageData, size);
		return false;
	}
};

/***********************************************************************************************************************
 * @brief Network output stream message container. (TCP)
 * @details See the @ref stream-message.h
 */
class OutStreamMessage : public StreamMessage
{
protected:
	uint8_t* buffer = nullptr;
	size_t size = 0;
public:
	/**
	 * @brief Creates a new output stream message. (TCP)
	 * @details See the @ref createStreamMessage().
	 *
	 * @param[in,out] buffer message data buffer
	 * @param bufferSize message buffer size in bytes
	 * @param messageSize message size in bytes
	 * @param lengthSize message header length size in bytes
	 */
	OutStreamMessage(uint8_t* buffer, size_t bufferSize, size_t messageSize, uint8_t lengthSize) noexcept :
		buffer(buffer), size(messageSize + lengthSize)
	{
		auto message = createStreamMessage(buffer, bufferSize, messageSize, lengthSize);
		iter = message.iter; end = message.end;
	}
	/**
	 * @brief Creates a new output stream message. (TCP)
	 * @details See the @ref createStreamMessage().
	 *
	 * @param[in,out] buffer message data buffer
	 * @param messageSize message size in bytes
	 * @param lengthSize message header size in bytes
	 */
	OutStreamMessage(std::vector<uint8_t>& buffer, size_t messageSize, uint8_t lengthSize) noexcept :
		size(messageSize + lengthSize)
	{
		if (buffer.size() < size) buffer.resize(size); this->buffer = buffer.data();
		auto message = createStreamMessage(buffer.data(), buffer.size(), messageSize, lengthSize);
		iter = message.iter; end = message.end;
	}
	/**
	 * @brief Creates a new empty output stream message.
	 */
	OutStreamMessage() noexcept = default;

	/**
	 * @brief Returns stream message buffer.
	 */
	const uint8_t* getBuffer() const noexcept { return buffer; }
	/**
	 * @brief Returns stream message size in bytes.
	 */
	size_t getSize() const noexcept { return size; }

	/**
	 * @brief Writes data to the stream message and advances offset.
	 * @details See the @ref writeStreamMessage().
	 * @return True if no more space to write data, otherwise false.
	 *
	 * @param[in] data message data to write
	 * @param count message byte count to write
	 */
	bool write(const void* data, size_t count) noexcept { return writeStreamMessage(this, data, count); }

	/*******************************************************************************************************************
	 * @brief Writes 8-bit unsigned integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageUint8().
	 * @return True if no more space to write data, otherwise false.
	 * @param value unsigned integer value to write
	 */
	bool write(uint8_t value) noexcept { return writeStreamMessageUint8(this, value); }
	/**
	 * @brief Writes 16-bit unsigned integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageUint16().
	 * @return True if no more space to write data, otherwise false.
	 * @param value unsigned integer value to write
	 */
	bool write(uint16_t value) noexcept { return writeStreamMessageUint16(this, value); }
	/**
	 * @brief Writes 32-bit unsigned integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageUint32().
	 * @return True if no more space to write data, otherwise false.
	 * @param value unsigned integer value to write
	 */
	bool write(uint32_t value) noexcept { return writeStreamMessageUint32(this, value); }
	/**
	 * @brief Writes 64-bit unsigned integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageUint64().
	 * @return True if no more space to write data, otherwise false.
	 * @param value unsigned integer value to write
	 */
	bool write(uint64_t value) noexcept { return writeStreamMessageUint64(this, value); }

	/**
	 * @brief Writes 8-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageInt8().
	 * @return True if no more space to write data, otherwise false.
	 * @param value signed integer value to write
	 */
	bool write(int8_t value) noexcept { return writeStreamMessageInt8(this, value); }
	/**
	 * @brief Writes 16-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageInt16().
	 * @return True if no more space to write data, otherwise false.
	 * @param value signed integer value to write
	 */
	bool write(int16_t value) noexcept { return writeStreamMessageInt16(this, value); }
	/**
	 * @brief Writes 32-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageInt32().
	 * @return True if no more space to write data, otherwise false.
	 * @param value signed integer value to write
	 */
	bool write(int32_t value) noexcept { return writeStreamMessageInt32(this, value); }
	/**
	 * @brief Writes 64-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageInt64().
	 * @return True if no more space to write data, otherwise false.
	 * @param value signed integer value to write
	 */
	bool write(int64_t value) noexcept { return writeStreamMessageInt64(this, value); }

	/*******************************************************************************************************************
	 * @brief Writes 32-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageFloat32().
	 * @return True if no more space to write data, otherwise false.
	 * @param value floating point value to write
	 */
	bool write(float value) noexcept { return writeStreamMessageFloat32(this, value); }
	/**
	 * @brief Writes 64-bit signed integer value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageFloat64().
	 * @return True if no more space to write data, otherwise false.
	 * @param value floating point value to write
	 */
	bool write(double value) noexcept { return writeStreamMessageFloat64(this, value); }

	/**
	 * @brief Writes string to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageData().
	 * @return True if no more space to write data, otherwise false.
	 *
	 * @param value message string to write
	 * @param lengthSize length of the string size in bytes
	 */
	bool write(std::string_view value, uint8_t lengthSize) noexcept
	{
		return writeStreamMessageData(this, value.data(), value.length(), lengthSize);
	}
	/**
	 * @brief Writes boolean value to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageBool().
	 * @return True if no more space to write data, otherwise false.
	 * @param value boolean value to write
	 */
	bool write(bool value) noexcept { return writeStreamMessageBool(this, value); }

	/**
	 * @brief Writes data to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageData().
	 * @return True if no more space to write data, otherwise false.
	 *
	 * @param[in] data message data to write
	 * @param dataSize size of the data in bytes
	 * @param lengthSize length of the data size in bytes
	 */
	bool write(const void* data, size_t dataSize, uint8_t lengthSize) noexcept
	{
		return writeStreamMessageData(this, data, dataSize, lengthSize);
	}
	/**
	 * @brief Writes vector data to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageData().
	 * @return True if no more space to write data, otherwise false.
	 *
	 * @tparam T type of the vector data
	 * @param[in] data message data vector to write
	 * @param lengthSize length of the data size in bytes
	 */
	template<class T>
	bool write(const std::vector<T>& data, uint8_t lengthSize) noexcept
	{
		return writeStreamMessageData(this, data.data(), data.size() * sizeof(T), lengthSize);
	}
	/**
	 * @brief Writes array data to the stream message and advances offset.
	 * @details See the @ref writeStreamMessageData().
	 * @return True if no more space to write data, otherwise false.
	 *
	 * @tparam T type of the array data
	 * @tparam S size of the array
	 * @param[in] data message data array to write
	 * @param lengthSize length of the data size in bytes
	 */
	template<class T, size_t N>
	bool write(const std::array<T, N>& data, uint8_t lengthSize) noexcept
	{
		return writeStreamMessageData(this, data.data(), data.size() * sizeof(T), lengthSize);
	}
};

} // namespace nets