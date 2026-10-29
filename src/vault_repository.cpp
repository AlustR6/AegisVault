#include "aegis/vault_repository.hpp"

#include <sodium.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace aegis
{
	namespace
	{
		// Binary format constants

        constexpr std::size_t CATALOG_PREFIX_SIZE = 28;

        constexpr std::size_t CREDENTIAL_PREFIX_SIZE = 44;

        constexpr std::size_t AUTH_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

        constexpr std::size_t MIN_CATALOG_CIPHERTEXT_SIZE =  6 + AUTH_TAG_SIZE;

        constexpr std::size_t MAX_CATALOG_CIPHERTEXT_SIZE = MAX_CATALOG_PLAINTEXT_BYTES + AUTH_TAG_SIZE;

        constexpr std::size_t MIN_CREDENTIAL_CIPHERTEXT_SIZE = 15 + AUTH_TAG_SIZE;

        constexpr std::size_t MAX_CREDENTIAL_CIPHERTEXT_SIZE = MAX_CREDENTIAL_PLAINTEXT_BYTES + AUTH_TAG_SIZE;

        constexpr DWORD IO_CHUNK_SIZE = 64 * 1024;

        // Binary cursor

        class BinaryCursor
        {
        public:
            
            explicit BinaryCursor(std::span<const unsigned char> bytes) : bytes_(bytes) {}

            [[nodiscard]] std::size_t position() const noexcept
            {
                return offset_;
            }

            [[nodiscard]] bool at_end() const noexcept
            {
                return offset_ == bytes_.size();
            }

            std::span<const unsigned char> take(std::size_t count)
            {
                if (offset_ > bytes_.size() || count > bytes_.size() - offset_)
                {
                    throw std::runtime_error("Vault corrupted or truncated.");
                }

                auto result = bytes_.subspan(offset_, count);

                offset_ += count;

                return result;
            }

            std::uint32_t read_u32()
            {
                auto bytes = take(4);

                std::uint32_t value = 0;

                for (std::size_t i = 0; i < 4; ++i)
                {
                    value |= static_cast<std::uint32_t>(bytes[i]) << (i * 8);
                }

                return value;
            }

        private:

            std::span<const unsigned char> bytes_;

            std::size_t offset_ = 0;
        };

        // LE reading

        std::uint32_t read_u32_le(std::span<const unsigned char> bytes)
        {
            if (bytes.size() != 4)
            {
                throw std::runtime_error("Invalid binary integer length.");
            }

            std::uint32_t value = 0;

            for (std::size_t i = 0; i < 4; ++i)
            {
                value |= static_cast<std::uint32_t>(bytes[i]) << (i * 8);
            }

            return value;
        }

        // LE writing

        void append_u32(std::vector<unsigned char>& output, std::uint32_t value)
        {
            for (std::size_t i = 0; i < 4; ++i)
            {
                output.push_back(static_cast<unsigned char>(value >> (i * 8)) & 0xFF);
            }
        }

        // Append binary data

        void append_bytes(std::vector<unsigned char>& destination, std::span<const unsigned char> source)
        {
            destination.insert(destination.end(), source.begin(), source.end());
        }

        // Windows error handling

        [[noreturn]] void throw_windows_error(const char* operation)
        {
            const DWORD error = GetLastError();

            throw std::system_error(static_cast<int>(error), std::system_category(), operation);
        }

        // RAII windows file handle

        class WindowsFileHandle
        {
        public:

            explicit WindowsFileHandle(HANDLE handle) : handle_(handle)
            {
                if (handle_ == INVALID_HANDLE_VALUE || handle_ == nullptr)
                {
                    throw std::runtime_error("Invalid Windows file handle.");
                }
            }

            WindowsFileHandle(const WindowsFileHandle&) = delete;

            WindowsFileHandle& operator=(const WindowsFileHandle&) = delete;

            ~WindowsFileHandle() noexcept
            {
                if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr)
                {
                    CloseHandle(handle_);
                }
            }

            HANDLE get() const noexcept
            {
                return handle_;
            }

            void close()
            {
                if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr)
                {
                    if (!CloseHandle(handle_))
                    {
                        throw_windows_error("CloseHandle");
                    }

                    handle_ = INVALID_HANDLE_VALUE;
                }
            }

        private:

            HANDLE handle_ = INVALID_HANDLE_VALUE;
        };

        // Temp fiel cleanup gaurd

        class TempFileGaurd
        {
        public:

            explicit TempFileGaurd(std::filesystem::path path) : path_(std::move(path)) {}

            TempFileGaurd(const TempFileGaurd&) = delete;

            TempFileGaurd& operator=(const TempFileGaurd&) = delete;

            ~TempFileGaurd() noexcept
            {
                if (active_)
                {
                    DeleteFileW(path_.c_str());
                }
            }

            void dismiss() noexcept
            {
                active_ = false;
            }

        private:

            std::filesystem::path path_;

            bool active_ = true;
        };

        // Generate random filename suffix

        std::wstring random_suffix()
        {
            std::array<unsigned char, 16> random{};

            randombytes_buf(random.data(), random.size());

            constexpr wchar_t HEX[] = L"0123456789abcdef";

            std::wstring result;

            result.reserve(32);

            for (unsigned char byte : random)
            {
                result.push_back(HEX[byte >> 4]);
                result.push_back(HEX[byte & 0x0F]);
            }

            return result;
        }

        // Construct sibling filepath

        std::filesystem::path sibling_path(const std::filesystem::path& target, const wchar_t* suffix)
        {
            const std::filesystem::path directory = target.has_parent_path() ? target.parent_path() : std::filesystem::path(L".");

            const std::wstring filename = target.filename().wstring() + suffix + random_suffix();

            return directory / filename;
        }

        // Write all bytes

        void write_all(HANDLE handle, std::span<const unsigned char> bytes)
        {
            std::size_t offset = 0;

            while (offset < bytes.size())
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, IO_CHUNK_SIZE));

                DWORD written = 0;

                if (!WriteFile(handle, bytes.data() + offset, requested, &written, nullptr))
                {
                    throw_windows_error("WriteFile");
                }

                if (written == 0 || written > requested)
                {
                    throw std::runtime_error("Unexpected file write result.");
                }

                offset += written;
            }
        }

        // Read all bytes

        std::vector<unsigned char> read_all(HANDLE handle)
        {
            LARGE_INTEGER file_size{};

            if (!GetFileSizeEx(handle, &file_size))
            {
                throw_windows_error("GetFileSizeEx");
            }

            if (file_size.QuadPart <= 0 || static_cast<unsigned long long>(file_size.QuadPart) > MAX_VAULT_FILE_BYTES)
            {
                throw std::runtime_error("Invalid vault file size.");
            }

            const std::size_t size = static_cast<std::size_t>(file_size.QuadPart);

            std::vector<unsigned char> bytes(size);

            std::size_t offset = 0;

            while (offset < bytes.size())
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, IO_CHUNK_SIZE));

                DWORD recieved = 0;

                if (!ReadFile(handle, bytes.data() + offset, requested, &recieved, nullptr))
                {
                    throw_windows_error("ReadFile");
                }

                if (recieved == 0 || recieved > requested)
                {
                    throw std::runtime_error("Vault file ended unexpectedly.");
                }

                offset += recieved;
            }

            return bytes;
        }

        // Create temp file

        HANDLE create_temp_file(const std::filesystem::path& target, std::filesystem::path& temp_path)
        {
            for (int attempt = 0; attempt < 8; ++attempt)
            {
                temp_path = sibling_path(target, L".tmp-");

                HANDLE handle = CreateFileW(temp_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);

                if (handle != INVALID_HANDLE_VALUE)
                {
                    return handle;
                }

                const DWORD error = GetLastError();

                if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
                {
                    throw_windows_error("Create temporary file");
                }
            }

            throw std::runtime_error("Unable to generate unique temporary filename.");
        }

        // Write a complete temp file

        void write_temp_file(HANDLE handle, std::span<const unsigned char> bytes)
        {
            WindowsFileHandle file(handle);

            write_all(file.get(), bytes);

            // Request that buffered data be flushed

            if (!FlushFileBuffers(file.get()))
            {
                throw_windows_error("FlushFileBuffers");
            }

            file.close();
        }

        // Create new file without overwriting

        void write_new_file(const std::filesystem::path& path, std::span<const unsigned char> bytes)
        {
            std::filesystem::path temp_path;

            HANDLE handle = create_temp_file(path, temp_path);

            TempFileGaurd cleanup(temp_path);

            write_temp_file(handle, bytes);

            if (!MoveFileExW(temp_path.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
            {
                throw_windows_error("Create vault file");
            }

            cleanup.dismiss();
        }

        // Replace an existing file

        void replace_existing_file(const std::filesystem::path& path, std::span<const unsigned char> bytes)
        {
            std::filesystem::path temp_path;

            HANDLE handle = create_temp_file(path, temp_path);

            TempFileGaurd cleanup(temp_path);

            write_temp_file(handle, bytes);

            // Create unique backup path for recovery

            const std::filesystem::path backup_path = sibling_path(path, L".backup-");

            // Refuse unexpected backup name collision

            const DWORD backup_attributes = GetFileAttributesW(backup_path.c_str());

            if (backup_attributes != INVALID_FILE_ATTRIBUTES)
            {
                throw std::runtime_error("Backup filename already exists.");
            }

            const DWORD backup_error = GetLastError();

            if (backup_error != ERROR_FILE_NOT_FOUND && backup_error != ERROR_PATH_NOT_FOUND)
            {
                throw_windows_error("Check backup filename");
            }

            if (!ReplaceFileW(path.c_str(), temp_path.c_str(), backup_path.c_str(), 0, nullptr, nullptr))
            {
                cleanup.dismiss();

                throw_windows_error("ReplaceFileW");
            }

            cleanup.dismiss();

            if (!DeleteFileW(backup_path.c_str()))
            {
                throw_windows_error("Vault saved, but backup cleanup failed");
            }
        }

        // Validate vault

        void authenticate_image(const VaultImage& image, const SecureBuffer& key)
        {
            verify_master_key(image.header, key, image.verification);

            DecryptedCatalog catalog = decrypt_catalog(image.header, key, image.catalog);

            catalog.verify_records(image.records);
        }
	}

    // Serialize vault image

    std::vector<unsigned char> serialize_vault_image(const VaultImage& image)
    {
        if (image.records.size() > MAX_CATALOG_ENTRIES)
        {
            throw std::invalid_argument("Too many credential records.");
        }

        const VaultHeaderBytes header = serialize_header(image.header);

        const VaultVerificationBytes verification = serialize_verification_record(image.verification);

        const std::vector<unsigned char> catalog = serialize_catalog_record(image.catalog);

        std::vector<unsigned char> output;

        append_bytes(output, header);
        append_bytes(output, verification);
        append_bytes(output, catalog);

        append_u32(output, static_cast<std::uint32_t>(image.records.size()));

        for (const EncryptedCredentialRecord& record : image.records)
        {
            const std::vector<unsigned char> bytes = serialize_credential_record(record);

            append_bytes(output, bytes);
        }

        if (output.size() > MAX_VAULT_FILE_BYTES)
        {
            throw std::runtime_error("Vault exceeds maximum supported size.");
        }

        return output;
    }

    // Deserialize vault image

    VaultImage deserialize_vault_image(std::span<const unsigned char> bytes)
    {
        if (bytes.size() > MAX_VAULT_FILE_BYTES)
        {
            throw std::runtime_error("Vault file exceeds maximum size.");
        }

        BinaryCursor cursor(bytes);

        VaultImage image;

        // Header

        image.header = deserialize_header(cursor.take(VAULT_HEADER_SIZE));

        // Verification record

        image.verification = deserialize_verification_record(cursor.take(VAULT_VERIFICATION_RECORD_SIZE));

        // Catalog

        const std::size_t catalog_start = cursor.position();

        const auto catalog_prefix = cursor.take(CATALOG_PREFIX_SIZE);

        const std::uint32_t catalog_length = read_u32_le(catalog_prefix.subspan(24, 4));

        if (catalog_length < MIN_CATALOG_CIPHERTEXT_SIZE || catalog_length > MAX_CATALOG_CIPHERTEXT_SIZE)
        {
            throw std::runtime_error("Invalid catalog ciphertext length.");
        }

        cursor.take(catalog_length);

        image.catalog = deserialize_catalog_record(bytes.subspan(catalog_start, CATALOG_PREFIX_SIZE + catalog_length));

        // Credential count

        const std::uint32_t count = cursor.read_u32();

        if (count > MAX_CATALOG_ENTRIES)
        {
            throw std::runtime_error("Vault credential count exceeds limit.");
        }

        image.records.reserve(count);

        // Encrypted credential records

        for (std::uint32_t i = 0; i < count; ++i)
        {
            const std::size_t record_start = cursor.position();

            const auto prefix = cursor.take(CREDENTIAL_PREFIX_SIZE);

            // Credential record length is at offset 40
            const std::uint32_t ciphertext_length = read_u32_le(prefix.subspan(40, 4));

            if (ciphertext_length < MIN_CREDENTIAL_CIPHERTEXT_SIZE || ciphertext_length > MAX_CREDENTIAL_CIPHERTEXT_SIZE)
            {
                throw std::runtime_error("Invalid credential ciphertext length.");
            }

            cursor.take(ciphertext_length);

            const auto record_bytes = bytes.subspan(record_start, CREDENTIAL_PREFIX_SIZE + ciphertext_length);

            image.records.push_back(deserialize_credential_record(record_bytes));
        }

        // Reject trailing bytes

        if (!cursor.at_end())
        {
            throw std::runtime_error("Unexpected trailing vault data.");
        }

        return image;
    }

    // Read vault file

    VaultImage read_vault_file(const std::filesystem::path& path)
    {
        WindowsFileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));

        std::vector<unsigned char> bytes = read_all(file.get());

        file.close();

        return deserialize_vault_image(bytes);
    }

    // Create new vault

    void create_new_vault(const std::filesystem::path& path, const SecureText& password, const KdfParameters& params)
    {
        VaultImage image;

        image.header = create_vault_header(params);

        SecureBuffer key = derive_master_key(password, image.header.salt, image.header.kdf);

        image.verification = create_verification_record(image.header, key);

        const std::span<const CatalogInput> empty_entries;

        image.catalog = encrypt_catalog(image.header, key, empty_entries);

        authenticate_image(image, key);

        const std::vector<unsigned char> bytes = serialize_vault_image(image);

        write_new_file(path, bytes);
    }

    // Open and authenticate existing vault

    UnlockedVault open_vault(const std::filesystem::path& path, const SecureText& password)
    {
        // Parse the file
        
        VaultImage image = read_vault_file(path);

        SecureBuffer key = unlock_master_key(image.header, password, image.verification);

        // Authenticate the catalog

        DecryptedCatalog catalog = decrypt_catalog(image.header, key, image.catalog);

        // Verify the entire credential collection

        catalog.verify_records(image.records);

        return UnlockedVault(std::move(image), std::move(key), std::move(catalog));
    }

    // Save updated vault

    void save_vault(const std::filesystem::path& path, const VaultImage& image, const SecureBuffer& key)
    {
        authenticate_image(image, key);

        const std::vector<unsigned char> bytes = serialize_vault_image(image);

        replace_existing_file(path, bytes);
    }
}