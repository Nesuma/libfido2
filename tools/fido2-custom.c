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

static void make_credential(void){
	const char	*path = NULL;
	fido_dev_t	*dev;
	size_t		 dev_infos_len = 0;
	fido_dev_info_t	*dev_infos = NULL;
	fido_cred_t	*cred = NULL;
	int return_code = 0;

	// retrieve device TODO error handling
	cred = fido_cred_new();
	dev_infos = fido_dev_info_new(16);
	fido_dev_info_manifest(dev_infos, 16, &dev_infos_len);
	dev = open_from_manifest(dev_infos, dev_infos_len, path);

	if(fido_dev_is_fido2(dev)) {
		printf("Yes is a fido2 device \n");
	} else {
		printf("Is not a FIDO2 device \n");
	}

	size_t bytes_in_challenge = 32;
	unsigned char challenge[bytes_in_challenge]; // size is not dynamic, no malloc necessary (automatic storage)
	fill_with_random_bytes(challenge,bytes_in_challenge);
	// unsigned char* challenge = get_random_bytes(bytes_in_challenge); // challenge is not null terminated
	
	char* call_type = "webauthn.create"; // is null terminated (because of this type of initialization)
	size_t bytes_in_call_type = sizeof(call_type)/sizeof(call_type[0]); // is an array in the current scope, sizeof should work
	char* call_origin = "controller-1234"; // is null terminated 
	size_t bytes_in_call_origin = sizeof(call_origin)/sizeof(call_origin[0]); // is an array in the current scope, sizeof should work

	size_t bytes_in_collected_client_data = bytes_in_challenge + bytes_in_call_origin + bytes_in_call_type;
	char *collected_client_data = malloc(sizeof(char) * bytes_in_collected_client_data);
	strcpy(collected_client_data, call_type);
	strcat(collected_client_data, call_origin);
	strcat(collected_client_data, (char *) challenge); // all signed char arrays

	// https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
	// https://rosettacode.org/wiki/SHA-256#C
	size_t bytes_in_hash = SHA256_DIGEST_LENGTH;
	unsigned char* client_data_hash[bytes_in_hash];
	SHA256((unsigned char*) collected_client_data, bytes_in_collected_client_data, client_data_hash);
	
	printf("hash: ");
	print_bits(client_data_hash,bytes_in_hash);
	printf("\n");
	
	// Type
	int	type = COSE_ES256;
	if ((return_code = fido_cred_set_type(cred, type)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s (0x%x)", fido_strerr(return_code), return_code);

	// Client data hash
	if ((return_code = fido_cred_set_clientdata_hash(cred,client_data_hash,bytes_in_hash)) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)", fido_strerr(return_code), return_code);

	// RP
	const char* rp_id = "localhost";
	const char* rp_name = "sandbox localhost";
	if ((return_code = fido_cred_set_rp(cred, rp_id, rp_name)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(return_code), return_code);

	// User
	const char* user_name = "1234-technician";
	const char* user_display_name = "Technician";
	const char* user_icon = NULL;
	size_t user_id_bytes = 32;
	
	unsigned char *user_id[user_id_bytes];
	fill_with_random_bytes(user_id,user_id_bytes);
	printf("Size of user id: %d \n", user_id_bytes);
	// TODO https://stackoverflow.com/questions/4054284/sizeof-for-a-null-terminated-const-char
	// kann so nicht funktionieren, sizeof() geht nur für array, bei pointer gibt es größe des pointers zurück
	if ((return_code = fido_cred_set_user(cred, user_id, user_id_bytes, user_name, user_display_name, user_icon)) != FIDO_OK)
		errx(1, "fido_cred_set_user: %s (0x%x)", fido_strerr(return_code), return_code);

	// Resident key
	if ((return_code = fido_cred_set_rk(cred, FIDO_OPT_TRUE)) != FIDO_OK)
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
	

	return_code = fido_dev_close(dev);
	fido_dev_free(&dev);
	fido_cred_free(&cred);

	printf("Final result code: %d \n", return_code);
	fido_strerr(return_code);

	free(collected_client_data);
}

int main(){
	make_credential();
}

// https://developers.yubico.com/libfido2/Manuals/fido_cred_verify.html
// The attestation statement formats supported by fido_cred_verify() are packed and fido-u2f. 
// The attestation type implemented by fido_cred_verify() is Basic Attestation. 
// The attestation key pair is assumed to be of the type ES256. 
// Other attestation formats and types are not supported. 