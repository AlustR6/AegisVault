#pragma once

#include "aegis/secure_buffer.hpp"

#include <cstddef>
#include <cstdint>

namespace aegis
{
	class SecureText
	{
	public:

		explicit SecureText(std::size_t capacity);

		SecureText(const SecureText&) = delete;
		SecureText& operator=(const SecureText&) = delete;

		SecureText(SecureText&& other) noexcept;
		SecureText& operator=(SecureText&& other) noexcept;

		void append_codepoint(char32_t codepoint);
		void backspace() noexcept;
		void clear() noexcept;

		[[nodiscard]] const unsigned char* data() const noexcept;
		[[nodiscard]] std::size_t size() const noexcept;
		[[nodiscard]] std::size_t capacity() const noexcept;
		[[nodiscard]] bool empty() const noexcept;

	private:

		SecureBuffer storage_;
		std::size_t used_ = 0;
	};
}