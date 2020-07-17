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

typedef struct fido_parameters{
	const char* rp_id;
	const char* rp_name;
	const char* user_name;
	const char* user_display_name;
	const char* user_icon;
} fido_parameters_t;

void get_fixed_parameters(fido_parameters_t* params){
	params->rp_id = "localhost";
	params->rp_name = "sandbox";
	params->user_name = "1234-technician";
	params->user_display_name= "Technician";
	params->user_icon = NULL;
}

static fido_dev_t *
open_from_manifest(const fido_dev_info_t *dev_infos, size_t len,
    const char *path)
{
	size_t i;
	fido_dev_t *dev;

	for (i = 0; i < len; i++) {
		const fido_dev_info_t *curr = fido_dev_info_ptr(dev_infos, i);
		if (path == NULL ||
		    strcmp(path, fido_dev_info_path(curr)) == 0) {
			dev = fido_dev_new_with_info(curr);
			if (fido_dev_open_with_info(dev) == FIDO_OK)
				return (dev);
			fido_dev_free(&dev);
		}
	}

	return (NULL);
}

static void fill_with_random_bytes(unsigned char* bytes,size_t amount){
	// array arguments are pointer parameters
	// I don't like that the function has to trust the caller, that "amount" memory is reserved for the array
	// But if this function would create an array with amount bytes and return it, the caller would have to trust 
	// the function, that the size is correct -> doesn't matter
	srand((unsigned int)time(NULL)); // intialize rng with unique seed

	for (size_t i = 0; i < amount; i++){
		*bytes++ = (unsigned char) rand(); // dereferenced pointer is set to random value before post incrementing the pointer
	}
}

// Howto: https://stackoverflow.com/questions/32675361/print-character-array-as-hex-in-c/32675416
static void print_bits(const unsigned char* hash, size_t length){
	for (size_t i = 0; i < length; i ++){
		printf("%02x ", *hash++);
	}
}

int get_client_data_hash(unsigned char* client_data_hash, size_t bytes_in_hash){
	// TODO Pattern for dependency injection?

	// Challenge
	size_t bytes_in_challenge = 32; // has to be larger than 16 bytes of entropy
	unsigned char challenge[bytes_in_challenge]; // size is not dynamic, no malloc necessary (automatic storage)
	fill_with_random_bytes(challenge,bytes_in_challenge);

	// Harcoded permanent values
	const char call_type[]= "webauthn.create"; // is null terminated (because of this type of initialization)
	size_t bytes_in_call_type = strlen(call_type); // is an array in the current scope, sizeof should work

	const char call_origin[] = "controller-1234"; // is null terminated 
	size_t bytes_in_call_origin = strlen(call_origin); // is an array in the current scope, sizeof should work
		
	// Collected client data
	size_t bytes_in_collected_client_data = bytes_in_challenge + bytes_in_call_origin + bytes_in_call_type;
	char *collected_client_data = malloc(sizeof(char) * bytes_in_collected_client_data);
	strcpy(collected_client_data, call_type);
	strcat(collected_client_data, call_origin);
	strcat(collected_client_data, (char *) challenge); // all signed char arrays

	// Hash of client data
	// https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
	// https://rosettacode.org/wiki/SHA-256#C
	SHA256((unsigned char*) collected_client_data, bytes_in_collected_client_data, client_data_hash);
	
	printf("hash: ");
	print_bits(client_data_hash,bytes_in_hash);
	printf("\n");

	free(collected_client_data);
	return 0;
}

// taken from tools/cred_make.c 
static void
print_attcred(const fido_cred_t *cred)
{
	printf("Result:\n");
	printf("Client data hash:\n");
	print_bits(fido_cred_clientdata_hash_ptr(cred),fido_cred_clientdata_hash_len(cred));
	printf("\nAuth data:\n");
	print_bits(fido_cred_authdata_ptr(cred),fido_cred_authdata_len(cred));
	printf("\nCredential id:\n");
	print_bits(fido_cred_id_ptr(cred), fido_cred_id_len(cred));
	printf("\nSignature:\n");
	print_bits(fido_cred_sig_ptr(cred), fido_cred_sig_len(cred));
	printf("\nPublic key:\n");
	print_bits(fido_cred_x5c_ptr(cred),fido_cred_x5c_len(cred));
	printf("\n");
}

// TODO Error handling
static int make_credential(fido_dev_t	*dev, const fido_parameters_t* parameters){
	fido_cred_t	*cred = NULL;
	int return_code = 0;

	cred = fido_cred_new();

	size_t bytes_in_hash = SHA256_DIGEST_LENGTH;
	unsigned char client_data_hash[bytes_in_hash];

	if(get_client_data_hash(client_data_hash,bytes_in_hash)){
		printf("Error occured in hashing of client data");
	}
	
	// Type
	int	type = COSE_ES256;
	if ((return_code = fido_cred_set_type(cred, type)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s (0x%x)", fido_strerr(return_code), return_code);

	// Client data hash
	if ((return_code = fido_cred_set_clientdata_hash(cred,client_data_hash,bytes_in_hash)) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)", fido_strerr(return_code), return_code);

	// RP
	if ((return_code = fido_cred_set_rp(cred, parameters->rp_id, parameters->rp_name)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(return_code), return_code);

	// User
	size_t bytes_in_user_id = 32;
	unsigned char user_id[bytes_in_user_id];
	fill_with_random_bytes(user_id,bytes_in_user_id);
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
	const char* pin = NULL;
	if ((return_code = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK)
		errx(1, "fido_dev_make_cred: %s (0x%x)", fido_strerr(return_code), return_code);

	print_attcred(cred);

	fido_cred_free(&cred);
	return return_code;
}

static int get_assertion(fido_dev_t* dev, const fido_parameters_t* parameters){
	fido_assert_t	*assert = NULL;
	const char	*pin = NULL;
	int		 type = COSE_ES256;
	int		 return_code;

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	// Client data hash
	size_t bytes_in_hash = SHA256_DIGEST_LENGTH;
	unsigned char client_data_hash[bytes_in_hash];

	if(get_client_data_hash(client_data_hash,bytes_in_hash)){
		printf("Error occured in hashing of client data");
	}

	return_code = fido_assert_set_clientdata_hash(assert, client_data_hash, bytes_in_hash);
	if (return_code != FIDO_OK) {
		errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	// RP
	return_code = fido_assert_set_rp(assert, parameters->rp_id);
	if (return_code != FIDO_OK){
		errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	// Assertion
	return_code = fido_dev_get_assert(dev, assert, pin);
	if (return_code != FIDO_OK) {
		errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(return_code), return_code);
	}

	return_code = fido_dev_close(dev);
	if (return_code != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(return_code), return_code);

	
	fido_assert_free(&assert);
	return return_code;
}


int main(){
	size_t		 dev_infos_len = 0;
	fido_dev_info_t	*dev_infos = NULL;
	const char	*path = NULL;
	fido_dev_t	*dev;
	int return_code = 0;
	// retrieve device TODO error handling

	fido_parameters_t fixed_params;

	// should be correct, the values are read only and stored at compile time, see
	// https://stackoverflow.com/questions/1011455/is-it-possible-to-modify-a-string-of-char-in-c
	get_fixed_parameters(&fixed_params);

	
	dev_infos = fido_dev_info_new(16);
	fido_dev_info_manifest(dev_infos, 16, &dev_infos_len);
	dev = open_from_manifest(dev_infos, dev_infos_len, path);

	if(fido_dev_is_fido2(dev)) {
		printf("Yes is a fido2 device \n");
	} else {
		printf("Is not a FIDO2 device \n");
	}

	return_code |= make_credential(dev, &fixed_params);

	// return_code |= get_assertion(dev, &fixed_params);

	return_code |= fido_dev_close(dev);
	fido_dev_free(&dev);

	return return_code;
}

// https://developers.yubico.com/libfido2/Manuals/fido_cred_verify.html
// The attestation statement formats supported by fido_cred_verify() are packed and fido-u2f. 
// The attestation type implemented by fido_cred_verify() is Basic Attestation. 
// The attestation key pair is assumed to be of the type ES256. 
// Other attestation formats and types are not supported. 