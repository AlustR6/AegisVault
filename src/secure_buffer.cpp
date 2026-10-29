#include "aegis/secure_buffer.hpp"

#include <sodium.h>

#include <new>
#include <stdexcept>
#include <utility>

namespace aegis
{
	SecureBuffer::SecureBuffer(std::size_t size)
	{
		if (size == 0) return;

		auto* allocated = static_cast<unsigned char*>(sodium_malloc(size));

		if (allocated == nullptr)
		{
			throw std::bad_alloc();
		}

		//Require memory locking
		if (sodium_mlock(allocated, size) != 0)
		{
			sodium_free(allocated);

			throw std::runtime_error("Failed to lock secure memory.");
		}

		//Init all allocated bytes to zero
		sodium_memzero(allocated, size);

		//Take ownership only after init is successful
		data_ = allocated;
		size_ = size;
	}

	SecureBuffer::~SecureBuffer() noexcept
	{
		release();
	}

	SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

	SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept
	{
		if (this != &other)
		{
			release();

			data_ = std::exchange(other.data_, nullptr);
			size_ = std::exchange(other.size_, 0);
		}

		return *this;
	}

	unsigned char* SecureBuffer::data() noexcept
	{
		return data_;
	}

	const unsigned char* SecureBuffer::data() const noexcept
	{
		return data_;
	}

	std::size_t SecureBuffer::size() const noexcept
	{
		return size_;
	}

	bool SecureBuffer::empty() const noexcept
	{
		return size_ == 0;
	}

	void SecureBuffer::clear() noexcept
	{
		if (data_ != nullptr)
		{
			sodium_memzero(data_, size_);
		}
	}

	void SecureBuffer::release() noexcept
	{
		if (data_ != nullptr)
		{
			sodium_memzero(data_, size_);
			sodium_free(data_);

			data_ = nullptr;
			size_ = 0;
		}
	}
}