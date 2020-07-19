#include <time.h>
#include <fido.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

// sleep
#include <unistd.h>

static const int REGISTRATION_ALLOWED = 1;

typedef struct fido_parameters
{
	const char *rp_id;
	const char *rp_name;
	const char *user_name;
	const char *user_display_name;
	const char *user_icon;
	int type;
} fido_parameters_t;

void get_fixed_parameters(fido_parameters_t *params)
{
	params->rp_id = "localhost";
	params->rp_name = "sandbox";
	params->user_name = "1234-technician";
	params->user_display_name = "Technician";
	params->user_icon = NULL;
	params->type = COSE_ES256;
}

static fido_dev_t *
open_from_manifest(const fido_dev_info_t *dev_infos, size_t len,
				   const char *path)
{
	size_t i;
	fido_dev_t *dev;

	for (i = 0; i < len; i++)
	{
		const fido_dev_info_t *curr = fido_dev_info_ptr(dev_infos, i);
		if (path == NULL ||
			strcmp(path, fido_dev_info_path(curr)) == 0)
		{
			dev = fido_dev_new_with_info(curr);
			if (fido_dev_open_with_info(dev) == FIDO_OK)
				return (dev);
			fido_dev_free(&dev);
		}
	}

	return (NULL);
}

static void fill_with_random_bytes(unsigned char *bytes, size_t amount)
{
	// array arguments are pointer parameters
	// I don't like that the function has to trust the caller, that "amount" memory is reserved for the array
	// But if this function would create an array with amount bytes and return it, the caller would have to trust
	// the function, that the size is correct -> doesn't matter
	srand((unsigned int)time(NULL)); // intialize rng with unique seed

	for (size_t i = 0; i < amount; i++)
	{
		*bytes++ = (unsigned char)rand(); // dereferenced pointer is set to random value before post incrementing the pointer
	}
}

// Howto: https://stackoverflow.com/questions/32675361/print-character-array-as-hex-in-c/32675416
static void print_bits(const unsigned char *hash, size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		printf("%02x ", *hash++);
	}
}

int get_client_data_hash(unsigned char *client_data_hash, size_t bytes_in_hash)
{
	// TODO Pattern for dependency injection?

	// Challenge
	size_t bytes_in_challenge = 32;				 // has to be larger than 16 bytes of entropy
	unsigned char challenge[bytes_in_challenge]; // size is not dynamic, no malloc necessary (automatic storage)
	fill_with_random_bytes(challenge, bytes_in_challenge);

	// Harcoded permanent values
	const char call_type[] = "webauthn.create";	   // is null terminated (because of this type of initialization)
	size_t bytes_in_call_type = strlen(call_type); // is an array in the current scope, sizeof should work

	const char call_origin[] = "controller-1234";	   // is null terminated
	size_t bytes_in_call_origin = strlen(call_origin); // is an array in the current scope, sizeof should work

	// Collected client data
	size_t bytes_in_collected_client_data = bytes_in_challenge + bytes_in_call_origin + bytes_in_call_type;
	char *collected_client_data = malloc(sizeof(char) * bytes_in_collected_client_data);
	strcpy(collected_client_data, call_type);
	strcat(collected_client_data, call_origin);
	strcat(collected_client_data, (char *)challenge); // all signed char arrays

	// Hash of client data
	// https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
	// https://rosettacode.org/wiki/SHA-256#C
	SHA256((unsigned char *)collected_client_data, bytes_in_collected_client_data, client_data_hash);

	printf("hash: ");
	print_bits(client_data_hash, bytes_in_hash);
	printf("\n");

	free(collected_client_data);
	return 0;
}

// taken from tools/cred_make.c
static void
print_attcred(const fido_cred_t *cred)
{
	FILE *out_f = NULL; 
	out_f = open_write("credential-debug");
	if (out_f != NULL){
		printf("\n\nSollte gehen\n\n");
	} else {
		printf("\n\nIst null\n\n");
	}
	char *cdh = NULL;
	char *authdata = NULL;
	char *id = NULL;
	char *sig = NULL;
	char *x5c = NULL;
	int r;

	r = base64_encode(fido_cred_clientdata_hash_ptr(cred),
					  fido_cred_clientdata_hash_len(cred), &cdh);
	r |= base64_encode(fido_cred_authdata_ptr(cred),
					   fido_cred_authdata_len(cred), &authdata);
	r |= base64_encode(fido_cred_id_ptr(cred), fido_cred_id_len(cred),
					   &id);
	r |= base64_encode(fido_cred_sig_ptr(cred), fido_cred_sig_len(cred),
					   &sig);
	if (fido_cred_x5c_ptr(cred) != NULL)
		r |= base64_encode(fido_cred_x5c_ptr(cred),
						   fido_cred_x5c_len(cred), &x5c);
	if (r < 0)
		errx(1, "output error");

	printf("Result:\n");
	printf("Client data hash hex:\n");
	print_bits(fido_cred_clientdata_hash_ptr(cred), fido_cred_clientdata_hash_len(cred));
	printf("\nClient data b64:\n");
	printf(cdh);
	printf("\nAuth data:\n");
	print_bits(fido_cred_authdata_ptr(cred), fido_cred_authdata_len(cred));
	printf("\nAuth data b64:\n");
	printf(authdata);
	printf("\nCredential id:\n");
	print_bits(fido_cred_id_ptr(cred), fido_cred_id_len(cred));
	printf("\nCredential id b64:\n");
	printf(id);
	printf("\nSignature:\n");
	print_bits(fido_cred_sig_ptr(cred), fido_cred_sig_len(cred));
	printf("\nSignature b64:\n");
	printf(sig);
	printf("\nPublic key:\n");
	print_bits(fido_cred_x5c_ptr(cred), fido_cred_x5c_len(cred));
	printf("\nPublic key b64:\n");
	printf(x5c);
	printf("\n");

	fprintf(out_f, "%s\n", cdh);
	fprintf(out_f, "%s\n", fido_cred_rp_id(cred));
	fprintf(out_f, "%s\n", fido_cred_fmt(cred));
	fprintf(out_f, "%s\n", authdata);
	fprintf(out_f, "%s\n", id);
	fprintf(out_f, "%s\n", sig);
	if (x5c != NULL)
		fprintf(out_f, "%s\n", x5c);

	free(cdh);
	free(authdata);
	free(id);
	free(sig);
	free(x5c);

	fclose(out_f);
}

// TODO Error handling
static int make_credential(fido_dev_t *dev, const fido_parameters_t *parameters, fido_cred_t *cred)
{
	int return_code = 0;

	size_t bytes_in_hash = SHA256_DIGEST_LENGTH;
	unsigned char client_data_hash[bytes_in_hash];

	if (get_client_data_hash(client_data_hash, bytes_in_hash))
	{
		printf("Error occured in hashing of client data");
	}

	// Type
	if ((return_code = fido_cred_set_type(cred, parameters->type)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s (0x%x)", fido_strerr(return_code), return_code);

	// Client data hash
	if ((return_code = fido_cred_set_clientdata_hash(cred, client_data_hash, bytes_in_hash)) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)", fido_strerr(return_code), return_code);

	// RP
	if ((return_code = fido_cred_set_rp(cred, parameters->rp_id, parameters->rp_name)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(return_code), return_code);

	// User
	size_t bytes_in_user_id = 32;
	unsigned char user_id[bytes_in_user_id];
	fill_with_random_bytes(user_id, bytes_in_user_id);
	if ((return_code = fido_cred_set_user(cred, user_id, bytes_in_user_id, parameters->user_name, parameters->user_display_name, parameters->user_icon)) != FIDO_OK)
		errx(1, "fido_cred_set_user: %s (0x%x)", fido_strerr(return_code), return_code);

	// Resident key
	if ((return_code = fido_cred_set_rk(cred, FIDO_OPT_FALSE)) != FIDO_OK)
		errx(1, "fido_cred_set_rk: %s (0x%x)", fido_strerr(return_code), return_code);

	// User verification
	// Yubikey can't verify user, can only omit
	if ((return_code = fido_cred_set_uv(cred, FIDO_OPT_OMIT)) != FIDO_OK)
		errx(1, "fido_cred_set_uv: %s (0x%x)", fido_strerr(return_code), return_code);

	// Create credential
	// No pin necessary if no pin set
	const char *pin = NULL;
	if ((return_code = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK)
		errx(1, "fido_dev_make_cred: %s (0x%x)", fido_strerr(return_code), return_code);

	return return_code;
}

static int get_assertion(fido_dev_t *dev, const fido_parameters_t *parameters, fido_assert_t *assert)
{

	const char *pin = NULL;
	// int type = COSE_ES256; never used and replaced with parameters
	int return_code;

	// Client data hash
	size_t bytes_in_hash = SHA256_DIGEST_LENGTH;
	unsigned char client_data_hash[bytes_in_hash];

	if (get_client_data_hash(client_data_hash, bytes_in_hash))
	{
		printf("Error occured in hashing of client data");
	}

	return_code = fido_assert_set_clientdata_hash(assert, client_data_hash, bytes_in_hash);
	if (return_code != FIDO_OK)
	{
		errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	// RP
	return_code = fido_assert_set_rp(assert, parameters->rp_id);
	if (return_code != FIDO_OK)
	{
		errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	// Assertion
	return_code = fido_dev_get_assert(dev, assert, pin);
	if (return_code != FIDO_OK)
	{
		printf("Assertion not possible: %s (0x%x)\n", fido_strerr(return_code), return_code);
		// errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	return return_code;
}

int authenticate_token(fido_dev_t *dev, const fido_parameters_t *fixed_params)
{
	int return_code = 0;
	fido_assert_t *assert = NULL;
	if ((assert = fido_assert_new()) == NULL)
	{
		errx(1, "fido_assert_new");
	}
	printf("Trying to authenticate\n");
	return_code = get_assertion(dev, fixed_params, assert);
	fido_assert_free(&assert);
	return return_code;
}

int register_token(fido_dev_t *dev, const fido_parameters_t *fixed_params)
{
	int return_code = 0;
	fido_cred_t *cred = NULL;

	// Make credential
	if ((cred = fido_cred_new()) == NULL)
	{
		errx(1, "fido_cred_new");
	}
	return_code = make_credential(dev, fixed_params, cred);
	print_attcred(cred);

	if(return_code){
		// stop on error
		return return_code;
	}
	// Verify authenticator response
	if (fido_cred_x5c_ptr(cred) == NULL) {
		if ((return_code |= fido_cred_verify_self(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify_self: %s", fido_strerr(return_code));
	} else {
		if ((return_code |= fido_cred_verify(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify: %s", fido_strerr(return_code));
	}

	// Store credentials
	FILE* cred_output_file = NULL;
	cred_output_file = open_write("credential");
	print_cred(cred_output_file, fixed_params->type, cred);
	fclose(cred_output_file);

	fido_cred_free(&cred);
	return return_code;
}

int main()
{
	size_t dev_infos_len = 0;
	fido_dev_info_t *dev_infos = NULL;
	const char *path = NULL;

	int return_code = 0;
	// retrieve device TODO error handling

	fido_parameters_t fixed_params;

	// should be correct, the values are read only and stored at compile time, see
	// https://stackoverflow.com/questions/1011455/is-it-possible-to-modify-a-string-of-char-in-c
	get_fixed_parameters(&fixed_params);

	int is_a_new_token = 1;

	while (true)
	{
		fido_dev_t *dev = NULL;
		dev_infos = fido_dev_info_new(16);
		fido_dev_info_manifest(dev_infos, 16, &dev_infos_len);
		dev = open_from_manifest(dev_infos, dev_infos_len, path);

		if (dev_infos_len > 0)
		{
			printf("%d devices detected\n", dev_infos_len);

			if (is_a_new_token)
			{
				return_code = authenticate_token(dev, &fixed_params);

				// registration only after assertion didn't work, need a better error handling system
				if(REGISTRATION_ALLOWED){
					printf("No credential registered on token, registering now\n");

					if(return_code = register_token(dev, &fixed_params)){
						printf("%d\n",return_code);
						return return_code;
					} else {
						printf("Successfully registered token\n");
					}
				}
			}
			is_a_new_token = 0; // inserted token was already used
			return_code |= fido_dev_close(dev);
			fido_dev_free(&dev);
		}
		else
		{
			printf("No devices detected\n");
			is_a_new_token = 1; // detected devices must be newly inserted
		}
		sleep(5);
	}
	return return_code;
}

// https://developers.yubico.com/libfido2/Manuals/fido_cred_verify.html
// The attestation statement formats supported by fido_cred_verify() are packed and fido-u2f.
// The attestation type implemented by fido_cred_verify() is Basic Attestation.
// The attestation key pair is assumed to be of the type ES256.
// Other attestation formats and types are not supported.