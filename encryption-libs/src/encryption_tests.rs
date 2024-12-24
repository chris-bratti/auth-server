#[cfg(test)]
pub mod test_encryption {
    use crate::{
        EncryptableString, EncryptionKey, HashableString, decrypt_string, encrypt_string,
        hash_field, verify_hash,
    };

    #[test]
    fn test_password_hashing() {
        let password = "whatALovelyL!ttleP@s$w0rd".to_string();

        let hashed_password = hash_field(&password.clone());

        assert!(hashed_password.is_ok());

        let hashed_password = hashed_password.unwrap();

        assert_ne!(password, hashed_password);

        let pass_match = verify_hash(&password, &hashed_password);

        assert!(pass_match.is_ok());

        assert_eq!(pass_match.unwrap(), true);
    }

    #[test]
    fn test_field_encryption() {
        let email = String::from("test@test.com");
        let encrypted_email = encrypt_string(&email, EncryptionKey::DatabaseEncryption)
            .expect("There was an error encrypting");

        assert_ne!(encrypted_email, email);

        let decrypted_email = decrypt_string(&encrypted_email, EncryptionKey::DatabaseEncryption)
            .expect("There was an error decrypting");

        assert_eq!(email, decrypted_email);
    }

    #[test]
    fn test_encryptable_string() {
        let unencrypted_val = String::from("sensitiveValue");

        let encrypted_string =
            encrypt_string(&unencrypted_val, crate::EncryptionKey::DatabaseEncryption).unwrap();

        let encryptable_string = EncryptableString::from(&unencrypted_val);

        // Test the eq_encrypted function
        assert!(encryptable_string.eq_encrypted(&encrypted_string));
        // Test the eq_unencrypted function
        assert!(encryptable_string.eq_decrypted(&unencrypted_val));

        // Manually decrypt and check encryptable_string decryption
        let decrypted_string =
            decrypt_string(&encrypted_string, crate::EncryptionKey::DatabaseEncryption).unwrap();

        assert_eq!(
            decrypted_string,
            encryptable_string.get_decrypted().to_string()
        );

        assert_eq!(
            unencrypted_val,
            encryptable_string.get_decrypted().to_string()
        );
    }

    #[test]
    fn test_hashable_string() {
        let original_val = String::from("supersecretAndSensitiveValue232323!!!jjfl");

        let hashable_string = HashableString::from(&original_val);

        assert!(hashable_string.verify(original_val).unwrap());

        assert_eq!(
            hashable_string
                .verify("Bogusvalueblahblahblah".to_string())
                .unwrap(),
            false
        );
    }
}
