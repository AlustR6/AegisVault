#include "aegis/terminal.hpp"
#include "aegis/vault_service.hpp"
#include "aegis/vault_repository.hpp"
#include "aegis/secure_buffer.hpp"
#include "aegis/secure_text.hpp"

#include <sodium.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>


namespace
{
    // ============================================================
    // Application Constants
    // ============================================================

    constexpr std::size_t MASTER_PASSWORD_LIMIT = 1024;

    constexpr std::size_t NAME_LIMIT =
        aegis::MAX_ENTRY_NAME_BYTES;

    constexpr std::size_t USERNAME_LIMIT =
        aegis::MAX_USERNAME_BYTES;

    constexpr std::size_t PASSWORD_LIMIT =
        aegis::MAX_PASSWORD_BYTES;

    // The current interactive input implementation supports
    // at most 4096 bytes per input field.
    //
    // The underlying credential format supports larger notes.

    constexpr std::size_t INTERACTIVE_NOTES_LIMIT = 4096;

    constexpr std::size_t MAX_COMMAND_LENGTH = 64;


    // ============================================================
    // Verify Interactive Console
    // ============================================================

    HANDLE require_console(DWORD handle_type)
    {
        HANDLE handle = GetStdHandle(handle_type);

        if (handle == nullptr ||
            handle == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error(
                "Unable to access the Windows console."
            );
        }

        DWORD mode = 0;

        if (!GetConsoleMode(handle, &mode))
        {
            throw std::runtime_error(
                "Aegis Vault requires an interactive console."
            );
        }

        return handle;
    }


    // ============================================================
    // Restore Console Mode Automatically
    // ============================================================

    class ConsoleModeRestore
    {
    public:

        ConsoleModeRestore(
            HANDLE handle,
            DWORD original_mode) noexcept

            : handle_(handle),
            original_mode_(original_mode)
        {
        }


        ConsoleModeRestore(const ConsoleModeRestore&) = delete;

        ConsoleModeRestore& operator=(
            const ConsoleModeRestore&) = delete;


        ~ConsoleModeRestore() noexcept
        {
            SetConsoleMode(
                handle_,
                original_mode_
            );
        }


    private:

        HANDLE handle_;

        DWORD original_mode_;
    };


    // ============================================================
    // Read Visible Console Command
    // ============================================================

    std::wstring read_command(
        std::string_view prompt)
    {
        std::cout << prompt << std::flush;

        HANDLE input = require_console(
            STD_INPUT_HANDLE
        );

        DWORD original_mode = 0;

        if (!GetConsoleMode(input, &original_mode))
        {
            throw std::runtime_error(
                "Unable to read console mode."
            );
        }

        // Enable normal visible, line-based input.

        DWORD command_mode =
            original_mode |
            ENABLE_LINE_INPUT |
            ENABLE_ECHO_INPUT |
            ENABLE_PROCESSED_INPUT;

        command_mode &=
            ~ENABLE_VIRTUAL_TERMINAL_INPUT;

        if (!SetConsoleMode(input, command_mode))
        {
            throw std::runtime_error(
                "Unable to configure console input."
            );
        }

        ConsoleModeRestore restore(
            input,
            original_mode
        );

        std::wstring command;

        bool too_long = false;

        // ReadConsoleW may return part of a long line.
        // Continue reading until the line terminator is seen.

        std::array<wchar_t, 64> buffer{};

        bool finished = false;

        while (!finished)
        {
            DWORD characters_read = 0;

            if (!ReadConsoleW(
                input,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &characters_read,
                nullptr))
            {
                throw std::runtime_error(
                    "Failed to read console command."
                );
            }

            if (characters_read == 0)
            {
                throw std::runtime_error(
                    "Console input closed."
                );
            }

            for (DWORD i = 0; i < characters_read; ++i)
            {
                const wchar_t character = buffer[i];

                if (character == L'\r' ||
                    character == L'\n')
                {
                    finished = true;
                    break;
                }

                if (command.size() < MAX_COMMAND_LENGTH)
                {
                    command.push_back(character);
                }
                else
                {
                    too_long = true;
                }
            }
        }

        if (too_long)
        {
            throw std::invalid_argument(
                "Command is too long."
            );
        }

        // Remove surrounding spaces and tabs.

        const std::size_t first =
            command.find_first_not_of(L" \t");

        if (first == std::wstring::npos)
        {
            return {};
        }

        const std::size_t last =
            command.find_last_not_of(L" \t");

        return command.substr(
            first,
            last - first + 1
        );
    }


    // ============================================================
    // Read Sensitive Input
    // ============================================================

    aegis::SecureText read_secure(
        std::string_view prompt,
        std::size_t maximum_bytes,
        bool required = true)
    {
        aegis::SecureText value =
            aegis::read_hidden_input(
                prompt,
                maximum_bytes
            );

        if (required && value.empty())
        {
            throw std::invalid_argument(
                "This field cannot be empty."
            );
        }

        return value;
    }


    // ============================================================
    // Compare Two SecureText Values
    // ============================================================

    bool secure_text_equal(
        const aegis::SecureText& first,
        const aegis::SecureText& second)
    {
        if (first.size() != second.size())
        {
            return false;
        }

        if (first.empty())
        {
            return true;
        }

        return sodium_memcmp(
            first.data(),
            second.data(),
            first.size()
        ) == 0;
    }


    // ============================================================
    // Read Password With Confirmation
    // ============================================================

    aegis::SecureText read_confirmed_password(
        std::string_view prompt,
        std::string_view confirmation_prompt,
        std::size_t maximum_bytes)
    {
        aegis::SecureText password = read_secure(
            prompt,
            maximum_bytes
        );

        aegis::SecureText confirmation = read_secure(
            confirmation_prompt,
            maximum_bytes
        );

        if (!secure_text_equal(
            password,
            confirmation))
        {
            throw std::runtime_error(
                "Passwords do not match."
            );
        }

        // The confirmation copy is no longer necessary.

        confirmation.clear();

        return password;
    }


    // ============================================================
    // Write Unicode Directly to the Console
    // ============================================================

    void write_console_wide(
        const wchar_t* characters,
        std::size_t length)
    {
        if (length == 0)
        {
            return;
        }

        HANDLE output = require_console(
            STD_OUTPUT_HANDLE
        );

        while (length > 0)
        {
            const DWORD requested =
                static_cast<DWORD>(
                    std::min<std::size_t>(
                        length,
                        4096
                    )
                    );

            DWORD written = 0;

            if (!WriteConsoleW(
                output,
                characters,
                requested,
                &written,
                nullptr))
            {
                throw std::runtime_error(
                    "Console output failed."
                );
            }

            if (written == 0 || written > requested)
            {
                throw std::runtime_error(
                    "Incomplete console output."
                );
            }

            characters += written;
            length -= written;
        }
    }


    // ============================================================
    // Identify Unsafe Display Characters
    // ============================================================

    bool should_escape(wchar_t character) noexcept
    {
        const auto value =
            static_cast<std::uint32_t>(character);

        // ASCII and C1 control characters.

        if (value < 0x20 ||
            (value >= 0x7F && value <= 0x9F))
        {
            return true;
        }

        // Unicode bidirectional formatting characters.

        if (value == 0x200E ||
            value == 0x200F ||
            (value >= 0x202A && value <= 0x202E) ||
            (value >= 0x2066 && value <= 0x2069))
        {
            return true;
        }

        return false;
    }


    // ============================================================
    // Write Escaped Unicode Character
    // ============================================================

    void write_escaped_character(
        wchar_t character)
    {
        constexpr wchar_t HEX[] =
            L"0123456789ABCDEF";

        const std::uint32_t value =
            static_cast<std::uint32_t>(character);

        wchar_t escaped[6]{
            L'\\',
            L'u',
            HEX[(value >> 12) & 0x0F],
            HEX[(value >> 8) & 0x0F],
            HEX[(value >> 4) & 0x0F],
            HEX[value & 0x0F]
        };

        write_console_wide(
            escaped,
            6
        );
    }


    // ============================================================
    // Display Protected UTF-8 Without Ordinary String Copies
    // ============================================================

    void display_protected_text(
        std::span<const unsigned char> utf8)
    {
        if (utf8.empty())
        {
            std::cout << "(empty)" << std::flush;
            return;
        }

        if (utf8.size() > INT_MAX)
        {
            throw std::runtime_error(
                "Text exceeds console display limit."
            );
        }

        const char* source =
            reinterpret_cast<const char*>(
                utf8.data()
                );

        const int source_length =
            static_cast<int>(utf8.size());

        // Determine the required UTF-16 length.

        const int required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            source,
            source_length,
            nullptr,
            0
        );

        if (required <= 0)
        {
            throw std::runtime_error(
                "Credential contains invalid UTF-8."
            );
        }

        // The UTF-16 copy is also sensitive.
        // Keep it in protected memory.

        aegis::SecureBuffer converted(
            static_cast<std::size_t>(required) *
            sizeof(wchar_t)
        );

        wchar_t* wide =
            reinterpret_cast<wchar_t*>(
                converted.data()
                );

        const int converted_count = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            source,
            source_length,
            wide,
            required
        );

        if (converted_count != required)
        {
            throw std::runtime_error(
                "UTF-8 conversion failed."
            );
        }

        // Flush ordinary output before using WriteConsoleW.

        std::cout.flush();

        // Display printable Unicode directly.
        // Escape controls and bidi-formatting characters.

        std::size_t segment_start = 0;

        const std::size_t total =
            static_cast<std::size_t>(required);

        for (std::size_t i = 0; i < total; ++i)
        {
            if (!should_escape(wide[i]))
            {
                continue;
            }

            write_console_wide(
                wide + segment_start,
                i - segment_start
            );

            write_escaped_character(wide[i]);

            segment_start = i + 1;
        }

        write_console_wide(
            wide + segment_start,
            total - segment_start
        );
    }


    // ============================================================
    // Print Help
    // ============================================================

    void print_help()
    {
        std::cout
            << "\n"
            << "Available Commands\n"
            << "------------------------------\n"
            << "help    Show available commands\n"
            << "add     Add a credential\n"
            << "get     Retrieve a credential\n"
            << "list    List credential names\n"
            << "update  Update a credential\n"
            << "rm      Remove a credential\n"
            << "lock    Lock and close the vault\n"
            << "exit    Exit Aegis Vault\n"
            << "\n";
    }


    // ============================================================
    // Add Credential
    // ============================================================

    void command_add(aegis::VaultService& vault)
    {
        std::cout << "\nAdd Credential\n";
        std::cout << "------------------------------\n";

        auto name = read_secure(
            "Credential name (hidden): ",
            NAME_LIMIT
        );

        auto username = read_secure(
            "Username (hidden, optional): ",
            USERNAME_LIMIT,
            false
        );

        auto password = read_confirmed_password(
            "Password (hidden): ",
            "Confirm password (hidden): ",
            PASSWORD_LIMIT
        );

        auto notes = read_secure(
            "Notes (hidden, optional): ",
            INTERACTIVE_NOTES_LIMIT,
            false
        );

        vault.add(
            name,
            username,
            password,
            notes
        );

        std::cout
            << "\nCredential added successfully.\n\n";
    }


    // ============================================================
    // Get Credential
    // ============================================================

    void command_get(const aegis::VaultService& vault)
    {
        std::cout << "\nRetrieve Credential\n";

        auto name = read_secure(
            "Credential name (hidden): ",
            NAME_LIMIT
        );

        std::cout
            << "\n"
            << "This operation will display decrypted "
            << "credential information on your screen.\n";

        const std::wstring confirmation = read_command(
            "Type SHOW to continue: "
        );

        if (confirmation != L"SHOW")
        {
            std::cout << "Canceled.\n\n";
            return;
        }

        // Only decrypt after the user confirms.

        auto credential = vault.get(name);

        std::cout << "\nUsername: " << std::flush;

        display_protected_text(
            credential.username()
        );

        std::cout << "\nPassword: " << std::flush;

        display_protected_text(
            credential.password()
        );

        std::cout << "\nNotes: " << std::flush;

        display_protected_text(
            credential.notes()
        );

        std::cout << "\n\n";
    }


    // ============================================================
    // List Credentials
    // ============================================================

    void command_list(const aegis::VaultService& vault)
    {
        std::cout
            << "\nStored Credentials\n"
            << "------------------------------\n";

        if (vault.size() == 0)
        {
            std::cout << "Vault is empty.\n\n";
            return;
        }

        for (std::size_t i = 0; i < vault.size(); ++i)
        {
            std::cout
                << (i + 1)
                << ". "
                << std::flush;

            display_protected_text(
                vault.name_at(i)
            );

            std::cout << '\n';
        }

        std::cout << '\n';
    }


    // ============================================================
    // Update Credential
    // ============================================================

    void command_update(aegis::VaultService& vault)
    {
        std::cout << "\nUpdate Credential\n";

        auto name = read_secure(
            "Existing credential name (hidden): ",
            NAME_LIMIT
        );

        std::cout
            << "Enter all replacement fields.\n"
            << "This version replaces the entire credential.\n\n";

        auto username = read_secure(
            "New username (hidden, optional): ",
            USERNAME_LIMIT,
            false
        );

        auto password = read_confirmed_password(
            "New password (hidden): ",
            "Confirm new password (hidden): ",
            PASSWORD_LIMIT
        );

        auto notes = read_secure(
            "New notes (hidden, optional): ",
            INTERACTIVE_NOTES_LIMIT,
            false
        );

        vault.update(
            name,
            username,
            password,
            notes
        );

        std::cout
            << "\nCredential updated successfully.\n\n";
    }


    // ============================================================
    // Remove Credential
    // ============================================================

    void command_remove(aegis::VaultService& vault)
    {
        std::cout << "\nRemove Credential\n";

        auto name = read_secure(
            "Credential name (hidden): ",
            NAME_LIMIT
        );

        std::cout
            << "\n"
            << "This will remove the credential "
            << "from the active vault.\n";

        const std::wstring confirmation = read_command(
            "Type DELETE to confirm: "
        );

        if (confirmation != L"DELETE")
        {
            std::cout << "Canceled.\n\n";
            return;
        }

        vault.remove(name);

        std::cout
            << "\nCredential removed successfully.\n\n";
    }


    // ============================================================
    // Interactive Unlocked Session
    // ============================================================

    void run_session(aegis::VaultService& vault)
    {
        std::cout
            << "\nVault unlocked successfully.\n"
            << "Type 'help' for available commands.\n\n";

        while (true)
        {
            std::wstring command;

            try
            {
                command = read_command("aegis> ");
            }
            catch (const std::invalid_argument& error)
            {
                std::cerr
                    << "Error: "
                    << error.what()
                    << "\n\n";

                continue;
            }

            if (command.empty())
            {
                continue;
            }

            if (command == L"lock" ||
                command == L"exit")
            {
                std::cout
                    << "\nVault locked.\n";

                return;
            }

            try
            {
                if (command == L"help")
                {
                    print_help();
                }
                else if (command == L"add")
                {
                    command_add(vault);
                }
                else if (command == L"get")
                {
                    command_get(vault);
                }
                else if (command == L"list")
                {
                    command_list(vault);
                }
                else if (command == L"update")
                {
                    command_update(vault);
                }
                else if (command == L"rm")
                {
                    command_remove(vault);
                }
                else
                {
                    std::cout
                        << "Unknown command. "
                        << "Type 'help'.\n\n";
                }
            }
            catch (const std::exception& error)
            {
                std::cerr
                    << "\nOperation failed: "
                    << error.what()
                    << "\n\n";
            }
        }
    }


    // ============================================================
    // Initialize New Vault
    // ============================================================

    void initialize_vault(
        const std::filesystem::path& path)
    {
        std::cout
            << "\nAEGIS VAULT v0.1.0\n"
            << "------------------------------\n"
            << "Create a new encrypted vault.\n\n";

        auto password = read_confirmed_password(
            "Create master password: ",
            "Confirm master password: ",
            MASTER_PASSWORD_LIMIT
        );

        // Use libsodium's moderate Argon2id profile.
        //
        // Its parameters are stored in the vault header.

        const aegis::KdfParameters parameters{
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE
        };

        aegis::create_new_vault(
            path,
            password,
            parameters
        );

        password.clear();

        std::cout
            << "\nVault created successfully.\n";
    }


    // ============================================================
    // Unlock Existing Vault
    // ============================================================

    void unlock_vault(
        const std::filesystem::path& path)
    {
        std::cout
            << "\nAEGIS VAULT v0.1.0\n"
            << "------------------------------\n";

        auto password = read_secure(
            "Master password: ",
            MASTER_PASSWORD_LIMIT
        );

        aegis::VaultService vault =
            aegis::VaultService::open(
                path,
                password
            );

        // The master-password text is no longer needed.
        // The verified derived key is owned by VaultService.

        password.clear();

        run_session(vault);
    }


    // ============================================================
    // Print Usage
    // ============================================================

    void print_usage()
    {
        std::cout
            << "\nAEGIS VAULT v0.1.0\n\n"
            << "Usage:\n"
            << "  aegis_vault.exe init <file.avlt>\n"
            << "  aegis_vault.exe unlock <file.avlt>\n"
            << "\n"
            << "Options:\n"
            << "  --help    Display usage information\n"
            << "\n";
    }
}


// ============================================================
// Windows Unicode Application Entry Point
// ============================================================

int wmain(int argc, wchar_t* argv[])
{
    try
    {
        // libsodium must be initialized before use.

        if (sodium_init() < 0)
        {
            throw std::runtime_error(
                "libsodium initialization failed."
            );
        }

        if (argc == 2 &&
            std::wstring_view(argv[1]) == L"--help")
        {
            print_usage();
            return 0;
        }

        if (argc != 3)
        {
            print_usage();
            return 2;
        }

        // Windows provides Unicode command-line arguments.

        const std::wstring_view operation(argv[1]);

        const std::filesystem::path path(argv[2]);

        if (path.empty())
        {
            throw std::invalid_argument(
                "Vault path cannot be empty."
            );
        }

        if (operation != L"init" &&
            operation != L"unlock")
        {
            print_usage();
            return 2;
        }

        // Password input requires a real interactive console.
        // Reject redirected standard input or output.

        static_cast<void>(
            require_console(STD_INPUT_HANDLE)
            );

        static_cast<void>(
            require_console(STD_OUTPUT_HANDLE)
            );

        if (operation == L"init")
        {
            initialize_vault(path);
            return 0;
        }

        unlock_vault(path);

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr
            << "\nAegis Vault error: "
            << error.what()
            << '\n';

        return 1;
    }
}