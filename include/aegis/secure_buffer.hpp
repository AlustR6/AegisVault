#pragma once

#include <cstddef>

namespace aegis
{
	class SecureBuffer
	{
	public:

		//Constructors
		SecureBuffer() noexcept = default;

		explicit SecureBuffer(std::size_t size);

		//Destructor
		~SecureBuffer() noexcept;

		//Disable copying
		SecureBuffer(const SecureBuffer&) = delete;

		SecureBuffer& operator=(const SecureBuffer&) = delete;

		//Enable moving
		SecureBuffer(SecureBuffer&& other) noexcept;

		SecureBuffer& operator=(SecureBuffer&& other) noexcept;

		//Memory access
		[[nodiscard]] unsigned char* data() noexcept;

		[[nodiscard]] const unsigned char* data() const noexcept;

		[[nodiscard]] std::size_t size() const noexcept;

		[[nodiscard]] bool empty() const noexcept;

		//Securely erase buffer contents
		void clear() noexcept;

	private:

		//Release any owned allocation
		void release() noexcept;

		unsigned char* data_ = nullptr;

		std::size_t size_ = 0;
	};
}