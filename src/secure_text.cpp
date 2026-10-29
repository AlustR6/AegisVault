#include "aegis/secure_text.hpp"

#include <sodium.h>

#include <stdexcept>
#include <utility>

namespace aegis
{
	SecureText::SecureText(std::size_t capacity) : storage_(capacity) {}

	SecureText::SecureText(SecureText&& other) noexcept : storage_(std::move(other.storage_)), used_(std::exchange(other.used_, 0)) {}

	SecureText& SecureText::operator=(SecureText&& other) noexcept
	{
		if (this != &other)
		{
			storage_ = std::move(other.storage_);
			used_ = std::exchange(other.used_, 0);
		}

		return *this;
	}

	void SecureText::append_codepoint(char32_t codepoint)
	{
		//Reject control chars and invalid unicode code points
		if (codepoint < 0x20 || codepoint >= 0x7F && codepoint < 0xA0 || codepoint >= 0xD800 && codepoint <= 0xDFFF || codepoint > 0x10FFFF)
		{
			throw std::invalid_argument("Invalid password character.");
		}

		//Determine the number of UTF-8 bytes needed
		std::size_t required = 1;

		if (codepoint > 0xFFFF)
			required = 4;
		else if (codepoint > 0x7FF)
			required = 3;
		else if (codepoint > 0x7F)
			required = 2;

		//Prevent writing beyond the protected allocation
		if (required > storage_.size() - used_)
		{
			throw std::length_error("Maximum password length exceeded.");
		}

		unsigned char* output = storage_.data() + used_;

		//Encode the unicode code point into protected memory
		switch (required)
		{
		case 1:
			output[0] = static_cast<unsigned char>(codepoint);
			break;

		case 2:
			output[0] = static_cast<unsigned char>(0xC0 | (codepoint >> 6));
			output[1] = static_cast<unsigned char>(0x80 | (codepoint & 0x3F));
			break;
			
		case 3:
			output[0] = static_cast<unsigned char>(0xE0 | (codepoint >> 12));
			output[1] = static_cast<unsigned char>(0x80 | ((codepoint >> 6) & 0x3F));
			output[2] = static_cast<unsigned char>(0x80 | (codepoint & 0x3F));
			break;
			
		case 4:
			output[0] = static_cast<unsigned char>(0xF0 | (codepoint >> 18));
			output[1] = static_cast<unsigned char>(0x80 | ((codepoint >> 12) & 0x3F));
			output[2] = static_cast<unsigned char>(0x80 | ((codepoint >> 6) & 0x3F));
			output[3] = static_cast<unsigned char>(0x80 | (codepoint & 0x3F));
			break;
		}

		used_ += required;
	}

	void SecureText::backspace() noexcept
	{
		if (used_ == 0) return;

		//Find the beginning of the last UTF-8 character
		std::size_t start = used_ - 1;

		while (start > 0 && (storage_.data()[start] & 0xC0) == 0x80)
		{
			--start;
		}

		// Erase every byte belonging to that character
		sodium_memzero(storage_.data() + start, used_ - start);

		used_ = start;
	}

	void SecureText::clear() noexcept
	{
		storage_.clear();
		used_ = 0;
	}

	const unsigned char* SecureText::data() const noexcept
	{
		return storage_.data();
	}

	std::size_t SecureText::size() const noexcept
	{
		return used_;
	}

	std::size_t SecureText::capacity() const noexcept
	{
		return storage_.size();
	}

	bool SecureText::empty() const noexcept
	{
		return used_ == 0;
	}
}