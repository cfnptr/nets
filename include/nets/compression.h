// Copyright 2020-2023 Nikita Fediuchin. All rights reserved.
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
#include "nets/defines.h"
#include "zlib.h"

/*
 * Converts zlib error the NETS result.
 * result - zlib result value.
 */
inline static NetsResult zlibErrorToNetsResult(int result)
{
	switch (result)
	{
	default:
		return UNKNOWN_ERROR_NETS_RESULT;
	case Z_NEED_DICT:
	case Z_DATA_ERROR:
	case Z_STREAM_ERROR:
		return BAD_DATA_NETS_RESULT;
	case Z_MEM_ERROR:
	case Z_BUF_ERROR:
		return OUT_OF_MEMORY_NETS_RESULT;
	}
}
