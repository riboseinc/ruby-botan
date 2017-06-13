# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'ffi'

module LibBotan
  extend FFI::Library
  ffi_lib 'libbotan-2'

  # Versioning
  attach_function :botan_ffi_api_version,
                  [],
                  :uint32
  attach_function :botan_ffi_supports_api,
                  [:uint32],
                  :int
  attach_function :botan_version_string,
                  [],
                  :string
  attach_function :botan_version_major,
                  [],
                  :uint32
  attach_function :botan_version_minor,
                  [],
                  :uint32
  attach_function :botan_version_patch,
                  [],
                  :uint32
  attach_function :botan_version_datestamp,
                  [],
                  :uint32

  if botan_ffi_supports_api(20170327) != 0
    raise 'The Botan library does not support the FFI API expected by this version of the Ruby module'
  end

  # Utility Functions
  attach_function :botan_same_mem,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_hex_encode,
                  [:pointer, :size_t, :pointer, :uint32],
                  :int

  # Random Number Generators
  attach_function :botan_rng_init,
                  [:pointer, :string],
                  :int
  attach_function :botan_rng_get,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_rng_reseed,
                  [:pointer, :size_t],
                  :int
  attach_function :botan_rng_destroy,
                  [:pointer],
                  :int

  # Hash Functions
  attach_function :botan_hash_init,
                  [:pointer, :string, :uint32],
                  :int
  attach_function :botan_hash_copy_state,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_hash_output_length,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_hash_block_size,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_hash_update,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_hash_final,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_hash_clear,
                  [:pointer],
                  :int
  attach_function :botan_hash_destroy,
                  [:pointer],
                  :int
  # Missing implementation
  #attach_function :botan_hash_name,
  #                [:pointer, :string, :size_t],
  #                :int

  # Message Authentication Codes
  attach_function :botan_mac_init,
                  [:pointer, :string, :uint32],
                  :int
  attach_function :botan_mac_output_length,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mac_set_key,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mac_update,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mac_final,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mac_clear,
                  [:pointer],
                  :int
  attach_function :botan_mac_destroy,
                  [:pointer],
                  :int

  # Ciphers
  attach_function :botan_cipher_init,
                  [:pointer, :string, :uint32],
                  :int
  attach_function :botan_cipher_valid_nonce_length,
                  [:pointer, :size_t],
                  :int
  attach_function :botan_cipher_get_tag_length,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_cipher_get_default_nonce_length,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_cipher_get_update_granularity,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_cipher_query_keylen,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_cipher_set_key,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_cipher_set_associated_data,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_cipher_start,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_cipher_update,
                  [:pointer, :uint32, :pointer, :size_t, :pointer, :pointer, :size_t, :pointer],
                  :int
  attach_function :botan_cipher_clear,
                  [:pointer],
                  :int
  attach_function :botan_cipher_destroy,
                  [:pointer],
                  :int

  # PBKDF
  attach_function :botan_pbkdf,
                  [:string, :pointer, :size_t, :string, :pointer, :size_t, :size_t],
                  :int
  attach_function :botan_pbkdf_timed,
                  [:string, :pointer, :size_t, :string, :pointer, :size_t, :size_t, :pointer],
                  :int

  # KDF
  attach_function :botan_kdf,
                  [:string, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t],
                  :int

  # Password Hashing
  attach_function :botan_bcrypt_generate,
                  [:pointer, :pointer, :string, :pointer, :size_t, :uint32],
                  :int
  attach_function :botan_bcrypt_is_valid,
                  [:string, :pointer],
                  :int


  # Block Ciphers
  attach_function :botan_block_cipher_init,
                  [:pointer, :string],
                  :int
  attach_function :botan_block_cipher_destroy,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_clear,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_set_key,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_block_cipher_block_size,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_encrypt_blocks,
                  [:pointer, :pointer, :pointer, :size_t],
                  :int
  attach_function :botan_block_cipher_decrypt_blocks,
                  [:pointer, :pointer, :pointer, :size_t],
                  :int


  # Multiple Precision Integers
  attach_function :botan_mp_init,
                  [:pointer],
                  :int
  attach_function :botan_mp_destroy,
                  [:pointer],
                  :int
  attach_function :botan_mp_to_hex,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_to_str,
                  [:pointer, :uint8, :pointer, :pointer],
                  :int
  attach_function :botan_mp_clear,
                  [:pointer],
                  :int
  attach_function :botan_mp_set_from_int,
                  [:pointer, :int],
                  :int
  attach_function :botan_mp_set_from_mp,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_set_from_str,
                  [:pointer, :string],
                  :int
  attach_function :botan_mp_set_from_radix_str,
                  [:pointer, :string, :size_t],
                  :int
  attach_function :botan_mp_num_bits,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_num_bytes,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_to_bin,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_from_bin,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mp_to_uint32,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_is_positive,
                  [:pointer],
                  :int
  attach_function :botan_mp_is_negative,
                  [:pointer],
                  :int
  attach_function :botan_mp_flip_sign,
                  [:pointer],
                  :int
  attach_function :botan_mp_is_zero,
                  [:pointer],
                  :int
  attach_function :botan_mp_is_odd,
                  [:pointer],
                  :int
  attach_function :botan_mp_is_even,
                  [:pointer],
                  :int
  attach_function :botan_mp_add,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_sub,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_mul,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_div,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_mod_mul,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_equal,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_cmp,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_swap,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_mp_powmod,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_lshift,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mp_rshift,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mp_mod_inverse,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_rand_bits,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mp_rand_range,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_gcd,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_mp_is_prime,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_mp_get_bit,
                  [:pointer, :size_t],
                  :int
  attach_function :botan_mp_set_bit,
                  [:pointer, :size_t],
                  :int
  attach_function :botan_mp_clear_bit,
                  [:pointer, :size_t],
                  :int

  # Public Key Creation, Import and Export
  attach_function :botan_privkey_create,
                  [:pointer, :string, :string, :pointer],
                  :int
  attach_function :botan_privkey_check_key,
                  [:pointer, :pointer, :uint32],
                  :int
  attach_function :botan_privkey_create_rsa,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_privkey_create_ecdsa,
                  [:pointer, :pointer, :string],
                  :int
  attach_function :botan_privkey_create_ecdh,
                  [:pointer, :pointer, :string],
                  :int
  attach_function :botan_privkey_create_mceliece,
                  [:pointer, :pointer, :size_t, :size_t],
                  :int
  attach_function :botan_privkey_load,
                  [:pointer, :pointer, :pointer, :size_t, :string],
                  :int
  attach_function :botan_privkey_destroy,
                  [:pointer],
                  :int
  attach_function :botan_privkey_export,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  # Note: botan_privkey_export_encrypted is deprecated
  attach_function :botan_privkey_export_encrypted,
                  [:pointer, :pointer, :pointer, :pointer, :string, :string, :uint32],
                  :int
  attach_function :botan_privkey_export_encrypted_pbkdf_msec,
                  [:pointer, :pointer, :pointer, :pointer, :string, :uint32, :pointer, :string, :string, :uint32],
                  :int
  attach_function :botan_privkey_export_encrypted_pbkdf_iter,
                  [:pointer, :pointer, :pointer, :pointer, :string, :size_t, :string, :string, :uint32],
                  :int
  attach_function :botan_pubkey_load,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_privkey_export_pubkey,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_export,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pubkey_algo_name,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pubkey_check_key,
                  [:pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pubkey_estimated_strength,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_fingerprint,
                  [:pointer, :string, :pointer, :pointer],
                  :int
  attach_function :botan_pubkey_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pubkey_get_field,
                  [:pointer, :pointer, :string],
                  :int
  attach_function :botan_privkey_get_field,
                  [:pointer, :pointer, :string],
                  :int

  # RSA specific functions
  attach_function :botan_privkey_load_rsa,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_privkey_rsa_get_p,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_privkey_rsa_get_q,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_privkey_rsa_get_d,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_privkey_rsa_get_n,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_privkey_rsa_get_e,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_load_rsa,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pubkey_rsa_get_e,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_rsa_get_n,
                  [:pointer, :pointer],
                  :int

  # DSA specific functions
  attach_function :botan_privkey_load_dsa,
                  [:pointer, :pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pubkey_load_dsa,
                  [:pointer, :pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_privkey_dsa_get_x,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_p,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_q,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_g,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_y,
                  [:pointer, :pointer],
                  :int

  # ElGamal specific functions
  attach_function :botan_privkey_load_elgamal,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pubkey_load_elgamal,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int

  # Public Key Encryption/Decryption
  attach_function :botan_pk_op_encrypt_create,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pk_op_encrypt_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_encrypt,
                  [:pointer, :pointer, :pointer, :pointer, :pointer, :size_t],
                  :int
  attach_function :botan_pk_op_decrypt_create,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pk_op_decrypt_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_decrypt,
                  [:pointer, :pointer, :pointer, :pointer, :size_t],
                  :int

  # Signatures
  attach_function :botan_pk_op_sign_create,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pk_op_sign_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_sign_update,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_pk_op_sign_finish,
                  [:pointer, :pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pk_op_verify_create,
                  [:pointer, :pointer, :pointer, :uint32],
                  :int
  attach_function :botan_pk_op_verify_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_verify_update,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_pk_op_verify_finish,
                  [:pointer, :pointer, :size_t],
                  :int

  # Key Agreement
  attach_function :botan_pk_op_key_agreement_create,
                  [:pointer, :pointer, :string, :uint32],
                  :int
  attach_function :botan_pk_op_key_agreement_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_key_agreement_export_public,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_pk_op_key_agreement,
                  [:pointer, :pointer, :pointer, :pointer, :size_t, :pointer, :size_t],
                  :int
  attach_function :botan_mceies_encrypt,
                  [:pointer, :pointer, :string, :pointer, :size_t, :pointer, :size_t, :pointer, :pointer],
                  :int
  attach_function :botan_mceies_decrypt,
                  [:pointer, :string, :pointer, :size_t, :pointer, :size_t, :pointer, :pointer],
                  :int

  # X.509 Certificates
  attach_function :botan_x509_cert_load,
                  [:pointer, :pointer, :size_t],
                  :int
  attach_function :botan_x509_cert_load_file,
                  [:pointer, :string],
                  :int
  attach_function :botan_x509_cert_destroy,
                  [:pointer],
                  :int
  # Missing implementation
  #attach_function :botan_x509_cert_gen_selfsigned,
  #                [:pointer, :pointer, :pointer, :string, :string],
  #                :int
  attach_function :botan_x509_cert_get_time_starts,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_time_expires,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_fingerprint,
                  [:pointer, :string, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_serial_number,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_authority_key_id,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_subject_key_id,
                  [:pointer, :pointer, :pointer],
                  :int
  # Missing implementation
  #attach_function :botan_x509_cert_path_verify,
  #                [:pointer, :string],
  #                :int
  attach_function :botan_x509_cert_get_public_key_bits,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_public_key,
                  [:pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_issuer_dn,
                  [:pointer, :string, :size_t, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_get_subject_dn,
                  [:pointer, :string, :size_t, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_to_string,
                  [:pointer, :pointer, :pointer],
                  :int
  attach_function :botan_x509_cert_allowed_usage,
                  [:pointer, :uint],
                  :int


end # module

