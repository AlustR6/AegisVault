#include <iostream>
#include <cstdlib>
#include <sodium.h>
#include "aegis/terminal.hpp"
#include <exception>

int main()
{
	std::cout << "==========================\n";
	std::cout << "       AEGIS VAULT        \n";
	std::cout << "==========================\n";

	// init the libsodium library
	if (sodium_init() < 0)
	{
		std::cerr << "[ERROR]: Failed to init libsodium.\n";
		return EXIT_FAILURE;
	}

	std::cout << "[OK]: libsodium init success.\n\n";

	//display the installed version of libsodium
	std::cout << "libsodium Version: " << sodium_version_string() << '\n';

	//display the nonce size used.
	std::cout << "XChaCha20 Nonce Size: " << crypto_aead_xchacha20poly1305_ietf_NPUBBYTES << " bytes\n";

	//display the salt size required by argon2id
	std::cout << "Argon2id Salt Size: " << crypto_pwhash_SALTBYTES << " bytes\n";

	std::cout << "\n[OK] Cryptographic evnironment ready.\n";

	try
	{
		std::cout << "\n--- Secure Terminal Input Test ---\n\n";

		{
			aegis::SecureText password =
				aegis::read_hidden_input(
					"Enter a TEST password: "
				);

			if (password.empty())
			{
				std::cout << "[INFO] No password entered.\n";
			}
			else
			{
				std::cout << "[OK] Password received securely.\n";
			}

			// Password is automatically erased when it leaves scope.
		}

		std::cout << "[OK] SecureBuffer cleanup completed.\n";
	}
	catch (const std::exception& error)
	{
		std::cerr << "[ERROR] " << error.what() << '\n';

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}