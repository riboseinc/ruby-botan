# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'ffi'

# @api private
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

  if botan_ffi_supports_api(2017_03_27) != 0
    raise 'The Botan library does not support the FFI API expected by this' \
          ' version of the Ruby module'
  end

  # Utility Functions
  attach_function :botan_same_mem,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_hex_encode,
                  %i[pointer size_t pointer uint32],
                  :int

  # Random Number Generators
  attach_function :botan_rng_init,
                  %i[pointer string],
                  :int
  attach_function :botan_rng_get,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_rng_reseed,
                  %i[pointer size_t],
                  :int
  attach_function :botan_rng_destroy,
                  [:pointer],
                  :int

  # Hash Functions
  attach_function :botan_hash_init,
                  %i[pointer string uint32],
                  :int
  attach_function :botan_hash_copy_state,
                  %i[pointer pointer],
                  :int
  attach_function :botan_hash_output_length,
                  %i[pointer pointer],
                  :int
  attach_function :botan_hash_block_size,
                  %i[pointer pointer],
                  :int
  attach_function :botan_hash_update,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_hash_final,
                  %i[pointer pointer],
                  :int
  attach_function :botan_hash_clear,
                  [:pointer],
                  :int
  attach_function :botan_hash_destroy,
                  [:pointer],
                  :int
  # Missing implementation
  # attach_function :botan_hash_name,
  #                [:pointer, :string, :size_t],
  #                :int

  # Message Authentication Codes
  attach_function :botan_mac_init,
                  %i[pointer string uint32],
                  :int
  attach_function :botan_mac_output_length,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mac_set_key,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mac_update,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mac_final,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mac_clear,
                  [:pointer],
                  :int
  attach_function :botan_mac_destroy,
                  [:pointer],
                  :int

  # Ciphers
  attach_function :botan_cipher_init,
                  %i[pointer string uint32],
                  :int
  attach_function :botan_cipher_valid_nonce_length,
                  %i[pointer size_t],
                  :int
  attach_function :botan_cipher_get_tag_length,
                  %i[pointer pointer],
                  :int
  attach_function :botan_cipher_get_default_nonce_length,
                  %i[pointer pointer],
                  :int
  attach_function :botan_cipher_get_update_granularity,
                  %i[pointer pointer],
                  :int
  attach_function :botan_cipher_query_keylen,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_cipher_set_key,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_cipher_set_associated_data,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_cipher_start,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_cipher_update,
                  %i[pointer uint32 pointer size_t
                     pointer pointer size_t pointer],
                  :int
  attach_function :botan_cipher_clear,
                  [:pointer],
                  :int
  attach_function :botan_cipher_destroy,
                  [:pointer],
                  :int

  # PBKDF
  attach_function :botan_pbkdf,
                  %i[string pointer size_t string pointer size_t size_t],
                  :int
  attach_function :botan_pbkdf_timed,
                  %i[string pointer size_t string
                     pointer size_t size_t pointer],
                  :int

  # KDF
  attach_function :botan_kdf,
                  %i[string pointer size_t pointer size_t
                     pointer size_t pointer size_t],
                  :int

  # Password Hashing
  attach_function :botan_bcrypt_generate,
                  %i[pointer pointer string pointer size_t uint32],
                  :int
  attach_function :botan_bcrypt_is_valid,
                  %i[string pointer],
                  :int

  # Block Ciphers
  attach_function :botan_block_cipher_init,
                  %i[pointer string],
                  :int
  attach_function :botan_block_cipher_destroy,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_clear,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_set_key,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_block_cipher_block_size,
                  [:pointer],
                  :int
  attach_function :botan_block_cipher_encrypt_blocks,
                  %i[pointer pointer pointer size_t],
                  :int
  attach_function :botan_block_cipher_decrypt_blocks,
                  %i[pointer pointer pointer size_t],
                  :int

  # Multiple Precision Integers
  attach_function :botan_mp_init,
                  [:pointer],
                  :int
  attach_function :botan_mp_destroy,
                  [:pointer],
                  :int
  attach_function :botan_mp_to_hex,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_to_str,
                  %i[pointer uint8 pointer pointer],
                  :int
  attach_function :botan_mp_clear,
                  [:pointer],
                  :int
  attach_function :botan_mp_set_from_int,
                  %i[pointer int],
                  :int
  attach_function :botan_mp_set_from_mp,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_set_from_str,
                  %i[pointer string],
                  :int
  attach_function :botan_mp_set_from_radix_str,
                  %i[pointer string size_t],
                  :int
  attach_function :botan_mp_num_bits,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_num_bytes,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_to_bin,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_from_bin,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mp_to_uint32,
                  %i[pointer pointer],
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
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_sub,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_mul,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_div,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_mp_mod_mul,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_mp_equal,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_cmp,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_swap,
                  %i[pointer pointer],
                  :int
  attach_function :botan_mp_powmod,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_mp_lshift,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mp_rshift,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mp_mod_inverse,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_rand_bits,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mp_rand_range,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_mp_gcd,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_mp_is_prime,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_mp_get_bit,
                  %i[pointer size_t],
                  :int
  attach_function :botan_mp_set_bit,
                  %i[pointer size_t],
                  :int
  attach_function :botan_mp_clear_bit,
                  %i[pointer size_t],
                  :int

  # Public Key Creation, Import and Export
  attach_function :botan_privkey_create,
                  %i[pointer string string pointer],
                  :int
  attach_function :botan_privkey_check_key,
                  %i[pointer pointer uint32],
                  :int
  attach_function :botan_privkey_create_rsa,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_privkey_create_ecdsa,
                  %i[pointer pointer string],
                  :int
  attach_function :botan_privkey_create_ecdh,
                  %i[pointer pointer string],
                  :int
  attach_function :botan_privkey_create_mceliece,
                  %i[pointer pointer size_t size_t],
                  :int
  attach_function :botan_privkey_load,
                  %i[pointer pointer pointer size_t string],
                  :int
  attach_function :botan_privkey_destroy,
                  [:pointer],
                  :int
  attach_function :botan_privkey_export,
                  %i[pointer pointer pointer uint32],
                  :int
  # Note: botan_privkey_export_encrypted is deprecated
  attach_function :botan_privkey_export_encrypted,
                  %i[pointer pointer pointer pointer string string uint32],
                  :int
  attach_function :botan_privkey_export_encrypted_pbkdf_msec,
                  %i[pointer pointer pointer pointer string
                     uint32 pointer string string uint32],
                  :int
  attach_function :botan_privkey_export_encrypted_pbkdf_iter,
                  %i[pointer pointer pointer pointer
                     string size_t string string uint32],
                  :int
  attach_function :botan_pubkey_load,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_privkey_export_pubkey,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_export,
                  %i[pointer pointer pointer uint32],
                  :int
  attach_function :botan_pubkey_algo_name,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_pubkey_check_key,
                  %i[pointer pointer uint32],
                  :int
  attach_function :botan_pubkey_estimated_strength,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_fingerprint,
                  %i[pointer string pointer pointer],
                  :int
  attach_function :botan_pubkey_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pubkey_get_field,
                  %i[pointer pointer string],
                  :int
  attach_function :botan_privkey_get_field,
                  %i[pointer pointer string],
                  :int

  # RSA specific functions
  attach_function :botan_privkey_load_rsa,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_privkey_rsa_get_p,
                  %i[pointer pointer],
                  :int
  attach_function :botan_privkey_rsa_get_q,
                  %i[pointer pointer],
                  :int
  attach_function :botan_privkey_rsa_get_d,
                  %i[pointer pointer],
                  :int
  attach_function :botan_privkey_rsa_get_n,
                  %i[pointer pointer],
                  :int
  attach_function :botan_privkey_rsa_get_e,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_load_rsa,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_pubkey_rsa_get_e,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_rsa_get_n,
                  %i[pointer pointer],
                  :int

  # DSA specific functions
  attach_function :botan_privkey_load_dsa,
                  %i[pointer pointer pointer pointer pointer],
                  :int
  attach_function :botan_pubkey_load_dsa,
                  %i[pointer pointer pointer pointer pointer],
                  :int
  attach_function :botan_privkey_dsa_get_x,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_p,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_q,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_g,
                  %i[pointer pointer],
                  :int
  attach_function :botan_pubkey_dsa_get_y,
                  %i[pointer pointer],
                  :int

  # ElGamal specific functions
  attach_function :botan_privkey_load_elgamal,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_pubkey_load_elgamal,
                  %i[pointer pointer pointer pointer],
                  :int

  # Public Key Encryption/Decryption
  attach_function :botan_pk_op_encrypt_create,
                  %i[pointer pointer pointer uint32],
                  :int
  attach_function :botan_pk_op_encrypt_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_encrypt,
                  %i[pointer pointer pointer pointer pointer size_t],
                  :int
  attach_function :botan_pk_op_decrypt_create,
                  %i[pointer pointer pointer uint32],
                  :int
  attach_function :botan_pk_op_decrypt_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_decrypt,
                  %i[pointer pointer pointer pointer size_t],
                  :int

  # Signatures
  attach_function :botan_pk_op_sign_create,
                  %i[pointer pointer pointer uint32],
                  :int
  attach_function :botan_pk_op_sign_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_sign_update,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_pk_op_sign_finish,
                  %i[pointer pointer pointer pointer],
                  :int
  attach_function :botan_pk_op_verify_create,
                  %i[pointer pointer pointer uint32],
                  :int
  attach_function :botan_pk_op_verify_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_verify_update,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_pk_op_verify_finish,
                  %i[pointer pointer size_t],
                  :int

  # Key Agreement
  attach_function :botan_pk_op_key_agreement_create,
                  %i[pointer pointer string uint32],
                  :int
  attach_function :botan_pk_op_key_agreement_destroy,
                  [:pointer],
                  :int
  attach_function :botan_pk_op_key_agreement_export_public,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_pk_op_key_agreement,
                  %i[pointer pointer pointer pointer size_t pointer size_t],
                  :int
  attach_function :botan_mceies_encrypt,
                  %i[pointer pointer string pointer size_t
                     pointer size_t pointer pointer],
                  :int
  attach_function :botan_mceies_decrypt,
                  %i[pointer string pointer size_t
                     pointer size_t pointer pointer],
                  :int

  # X.509 Certificates
  attach_function :botan_x509_cert_load,
                  %i[pointer pointer size_t],
                  :int
  attach_function :botan_x509_cert_load_file,
                  %i[pointer string],
                  :int
  attach_function :botan_x509_cert_destroy,
                  [:pointer],
                  :int
  # Missing implementation
  # attach_function :botan_x509_cert_gen_selfsigned,
  #                [:pointer, :pointer, :pointer, :string, :string],
  #                :int
  attach_function :botan_x509_cert_get_time_starts,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_time_expires,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_fingerprint,
                  %i[pointer string pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_serial_number,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_authority_key_id,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_subject_key_id,
                  %i[pointer pointer pointer],
                  :int
  # Missing implementation
  # attach_function :botan_x509_cert_path_verify,
  #                [:pointer, :string],
  #                :int
  attach_function :botan_x509_cert_get_public_key_bits,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_public_key,
                  %i[pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_issuer_dn,
                  %i[pointer string size_t pointer pointer],
                  :int
  attach_function :botan_x509_cert_get_subject_dn,
                  %i[pointer string size_t pointer pointer],
                  :int
  attach_function :botan_x509_cert_to_string,
                  %i[pointer pointer pointer],
                  :int
  attach_function :botan_x509_cert_allowed_usage,
                  %i[pointer uint],
                  :int
end # module

