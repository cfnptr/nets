// Copyright 2020-2021 Nikita Fediuchin. All rights reserved.
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

#pragma once

#if __linux__
#include <byteswap.h>
#define swapBytes16(x) bswap_16(x)
#define swapBytes32(x) bswap_32(x)
#define swapBytes64(x) bswap_64(x)
#elif __APPLE__
#include <libkern/OSByteOrder.h>
#define swapBytes16(x) OSSwapInt16(x)
#define swapBytes32(x) OSSwapInt32(x)
#define swapBytes64(x) OSSwapInt64(x)
#elif _WIN32
#include <stdlib.h>
#define swapBytes16(x) _byteswap_ushort(x)
#define swapBytes32(x) _byteswap_ulong(x)
#define swapBytes64(x) _byteswap_uint64(x)
#endif

#if MPNW_LITTLE_ENDIAN
#define hostToNet16(x) swapBytes16(x)
#define hostToNet32(x) swapBytes32(x)
#define hostToNet64(x) swapBytes64(x)
#define netToHost16(x) swapBytes16(x)
#define netToHost32(x) swapBytes32(x)
#define netToHost64(x) swapBytes64(x)
#else
#define hostToNet16(x) (x)
#define hostToNet32(x) (x)
#define hostToNet64(x) (x)
#define netToHost16(x) (x)
#define netToHost32(x) (x)
#define netToHost64(x) (x)
#endif
