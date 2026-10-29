#pragma once

#include "aegis/secure_text.hpp"

#include <cstddef>
#include <string_view>

namespace aegis
{
	[[nodiscard]] SecureText read_hidden_input(std::string_view prompt, std::size_t _Ret_writes_bytes_maybenull_ = 1024);
}