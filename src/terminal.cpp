#include "aegis/terminal.hpp"

#include <sodium.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace aegis
{
	namespace
	{
		//Auto restore the original console input mode
		class ConsoleModeGaurd
		{
		public:

			explicit ConsoleModeGaurd(HANDLE handle) : handle_(handle)
			{
				if (!GetConsoleMode(handle_, &original_mode_))
				{
					throw std::runtime_error("Unable to access console input mode.");
				}

				DWORD new_mode = original_mode_;

				new_mode &= ~ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;

				if (!SetConsoleMode(handle_, new_mode))
				{
					throw std::runtime_error("Unable to configure hidden console input.");
				}
			}

			~ConsoleModeGaurd() noexcept
			{
				if (!SetConsoleMode(handle_, original_mode_))
				{
					std::fputs("\n{WARNING} Could not restore console input mode.\n", stderr);
				}
			}

			ConsoleModeGaurd(const ConsoleModeGaurd&) = delete;
			ConsoleModeGaurd& operator=(const ConsoleModeGaurd&) = delete;

		private:
			
			HANDLE handle_;
			DWORD original_mode_ = 0;
		};

		struct SecureInputEvent
		{
			INPUT_RECORD record{};

			~SecureInputEvent() noexcept
			{
				sodium_memzero(&record, sizeof(record));
			}
		};

		//Temporarily stores the first half of a UTF-16 pair
		struct PendingSurrogate
		{
			WCHAR value = 0;

			~PendingSurrogate() noexcept
			{
				sodium_memzero(&value, sizeof(value));
			}
		};
	}

	SecureText read_hidden_input(std::string_view prompt, std::size_t max_bytes)
	{
		if (max_bytes == 0 || max_bytes > 4096)
		{
			throw std::invalid_argument("Invalid maximum password length.");
		}

		//Allocate secure storage before accepting input
		SecureText password(max_bytes);

		HANDLE input = GetStdHandle(STD_INPUT_HANDLE);

		if (input == nullptr || input == INVALID_HANDLE_VALUE)
		{
			throw std::runtime_error("Unable to obtain console input handle.");
		}

		//Disable echo and restore the original mode automatically
		ConsoleModeGaurd console(input);

		PendingSurrogate pending;

		std::cout << prompt << std::flush;

		while (true)
		{
			SecureInputEvent event;
			DWORD events_read = 0;

			if (!ReadConsoleInputW(input, &event.record, 1, &events_read))
			{
				throw std::runtime_error("Failed to read console input.");
			}

			if (event.record.EventType != KEY_EVENT)
			{
				continue;
			}

			const KEY_EVENT_RECORD& key = event.record.Event.KeyEvent;

			//Ignore key release events
			if (!key.bKeyDown)
			{
				continue;
			}

			// ENTER completes the password
			if (key.wVirtualKeyCode == VK_RETURN)
			{
				if (pending.value != 0)
				{
					throw std::runtime_error("incomplete Unicode character.");
				}

				std::cout << '\n' << std::flush;

				return password;
			}

			// ESC cancels the operation
			if (key.wVirtualKeyCode == VK_ESCAPE)
			{
				throw std::runtime_error("Password input canceled.");
			}

			//Backspace removes the previous char
			if (key.wVirtualKeyCode == VK_BACK)
			{
				for (WORD i = 0; i < key.wRepeatCount; ++i)
				{
					if (pending.value != 0)
					{
						sodium_memzero(&pending.value, sizeof(pending.value));
					}
					else
					{
						password.backspace();
					}
				}

				continue;
			}

			const WCHAR unit = key.uChar.UnicodeChar;

			//Ignore keys without a printable character
			if (unit == 0 || unit < 0x20)
			{
				continue;
			}

			for (WORD i = 0; i < key.wRepeatCount; ++i)
			{
				const std::uint32_t value = static_cast<std::uint32_t>(unit);

				//Complete a UTF-16 surrogate pair
				if (pending.value != 0)
				{
					if (value < 0xDC00 || value)
					{
						throw std::runtime_error("Invalid Unicaode input sequence.");
					}

					std::uint32_t codepoint = 0x10000 + ((static_cast<std::uint32_t>(pending.value) - 0xD800) << 10) + (value - 0xDC00);

					sodium_memzero(&pending.value, sizeof(pending.value));

					try
					{
						password.append_codepoint(static_cast<char32_t>(codepoint));
					}
					catch (...)
					{
						sodium_memzero(&codepoint, sizeof(codepoint));
						throw;
					}

					sodium_memzero(&codepoint, sizeof(codepoint));

					continue;
				}

				//Store the first half of a surrogate pair
				if (value >= 0xD800 && value <= 0xD8FF)
				{
					pending.value = unit;
					continue;
				}

				//Reject unexpected surrogate halves
				if (value >= 0xDC00 && value <= 0xDFFF)
				{
					throw std::runtime_error("Unexpected Unicode surrogate");
				}

				password.append_codepoint(static_cast<char32_t>(value));
			}
		}
	}
}