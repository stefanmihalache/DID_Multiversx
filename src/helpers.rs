use multiversx_sc::imports::*;

extern crate alloc;
use alloc::string::ToString;


use crate::{
    structures::*,
    storage,
};

fn convert_to_hex<M: ManagedTypeApi>(hash: &ManagedByteArray<M, 32>) -> ManagedBuffer<M> {
    let mut hex_buffer = ManagedBuffer::new();
    for byte in hash.to_byte_array() {
        hex_buffer.append_bytes(&hex::encode_upper(&[byte]).as_bytes());
    }
    hex_buffer
}

#[multiversx_sc::module]
pub trait HelpersModule: storage::StorageModule {
    fn generate_did(&self, address: &ManagedAddress) -> ManagedBuffer {
        // Implementation for DID generation following W3C DID specification
        let mut prefix = ManagedBuffer::from("did:multiversx");

        // Hash the address using SHA-256
        let hashed_address = self.crypto().sha256(address.as_managed_buffer());

        // Convert ManagedByteArray to hex string manually
        let hex_hash = convert_to_hex(&hashed_address);

        // Combine prefix with the hashed address
        prefix.append(&hex_hash);

        // Return the did
        prefix
    }

    fn generate_schema_id(&self, type_: &ManagedBuffer, version: &ManagedBuffer) -> ManagedBuffer {
        // Concatenate type and version into a single buffer
        let mut concatenated = ManagedBuffer::new();
        concatenated.append(type_);
        concatenated.append(version);

        // Hash the concatenated buffer using SHA-256
        let hash = self.crypto().sha256(&concatenated);

        // Convert the hash to a hexadecimal string
        convert_to_hex(&hash)
    }

    // Verify Credential
    fn verify_credential<M: ManagedTypeApi>(
        &self,
        credential: &Credential<M>,
    ) -> Result<(), ManagedBuffer> {
        let current_timestamp = self.blockchain().get_block_timestamp();

        // Check if credential is revoked
        if credential.revoked {
            return Err(ManagedBuffer::from("Credential is revoked"));
        }

        // Check expiration
        if let Some(expiration_date) = credential.expiration_date {
            if current_timestamp > expiration_date {
                return Err(ManagedBuffer::from("Credential has expired"));
            }
        }

        // Verify proof
        if !self.verify_credential_proof(credential) {
            return Err(ManagedBuffer::from("Invalid credential proof"));
        }

        // If all checks pass
        Ok(())
    }

    // Revoke Credential
    fn revoke_credential(&self, credential: &mut Credential<Self::Api>) {
        credential.revoked = true;
    }

    // Helper: Generate Credential ID
    fn generate_credential_id(&self) -> ManagedBuffer<Self::Api> {
        let counter = self.next_credential_id().get();
        self.next_credential_id().set(counter + 1);

        let id_bytes = counter.to_be_bytes();
        ManagedBuffer::from(&id_bytes)
    }

    // Helper: Generate Credential Proof
    fn generate_credential_proof(
        &self,
        issuer: &ManagedAddress<Self::Api>,
        holder: &ManagedAddress<Self::Api>,
        merkle_root: ManagedBuffer<Self::Api>,
        created: u64,
    ) -> CredentialProof<Self::Api> {
        let mut data = ManagedBuffer::new();
        data.append(&issuer.as_managed_buffer());
        data.append(&holder.as_managed_buffer());
        data.append(&merkle_root);
        data.append(&ManagedBuffer::from(&created.to_be_bytes()));

        let signature_arr =self.crypto().sha256(&data);
        let signature = convert_to_hex(&signature_arr);

        CredentialProof {
            type_: ManagedBuffer::from("ProofType"), // Define your proof type
            created,
            verification_method: issuer.as_managed_buffer().clone(),
            signature,
        }
    }

    // Helper: Verify Credential Proof
    fn verify_credential_proof<M: ManagedTypeApi>(&self, credential: &Credential<M>) -> bool {
        let mut data = ManagedBuffer::new();

        // Append buffers to `data`
        data.append(&ManagedBuffer::from(credential.issuer.as_managed_buffer().to_boxed_bytes()));
        data.append(&ManagedBuffer::from(credential.holder.as_managed_buffer().to_boxed_bytes()));

        data.append(&ManagedBuffer::from(&credential.proof.created.to_be_bytes()));

        let encryption_key = ManagedBuffer::from(credential.encryption_key.to_boxed_bytes());
        let signature = ManagedBuffer::from(credential.proof.signature.to_boxed_bytes());


        let is_valid_signature = {
            self.crypto().verify_bls(
                &encryption_key,
                &data,
                &signature,
            );
            true // or false depending on your specific logic
        };

        is_valid_signature
    }

    fn validate_claims_against_schema(
        &self,
        claims: &Claims<Self::Api>,
        schema: &CredentialSchema<Self::Api>,
    ) {
        // Iterate through schema attributes
        for attribute in schema.attributes.iter() {
            // Check if the attribute exists in the claims
            let claim_value = claims.data.iter().find(|claim| claim.attribute == attribute.name);

            if attribute.required && claim_value.is_none() {
                sc_panic!("Missing required attribute: {}", attribute.name);
            }

            if let Some(claim) = claim_value {
                // Validate type consistency (example: assuming data type validation can be enforced)
                match attribute.data_type.to_string().as_str() {
                    "string" => { /* Additional checks for string type, if needed */ }
                    "integer" => {
                        if !self.is_integer(&claim.value) {
                            sc_panic!(
                            "Type mismatch for attribute {}: expected integer, found {}",
                            attribute.name,
                            claim.value
                        );
                        }
                    }
                    "boolean" => {
                        if !self.is_boolean(&claim.value) {
                            sc_panic!(
                            "Type mismatch for attribute {}: expected boolean, found {}",
                            attribute.name,
                            claim.value
                        );
                        }
                    }
                    _ => {
                        sc_panic!(
                        "Unsupported data type for attribute {}: {}",
                        attribute.name,
                        attribute.data_type
                    );
                    }
                }
                // Possibility to add constraints
            }
        }
    }

    fn is_integer(&self, value: &ManagedBuffer<Self::Api>) -> bool {
        value.to_string().parse::<i64>().is_ok()
    }

    fn is_boolean(&self, value: &ManagedBuffer<Self::Api>) -> bool {
        matches!(value.to_string().as_str(), "true" | "false")
    }

    fn managed_buffer_from_bytes(&self, bytes: &[u8]) -> ManagedBuffer<Self::Api> {
        ManagedBuffer::new_from_bytes(bytes)
    }

    fn verify_delegation(
        &self,
        delegation_id: u64,
        credential: &Credential<Self::Api>,
    ) -> bool {
        let delegation = self.delegations(&delegation_id).get();

        // Check if delegation is revoked
        if delegation.revoked {
            sc_panic!("Delegation {} is revoked", delegation_id);
        }

        // Check if delegation is expired
        let current_timestamp = self.blockchain().get_block_timestamp();
        if current_timestamp > delegation.valid_until {
            sc_panic!("Delegation {} has expired", delegation_id);
        }

        // Check if credential type is allowed under the delegation
        let credential_type_match = credential
            .credential_type
            .iter()
            .all(|type_| delegation.credential_types.contains(&*type_));

        if !credential_type_match {

            let joined_types = delegation
                .credential_types
                .iter()
                .fold(ManagedBuffer::new(), |mut acc, t| {
                    if !acc.is_empty() {
                        acc.append(&ManagedBuffer::from(", "));
                    }
                    acc.append(&*t);
                    acc
                });

            sc_panic!(
                "Delegation {} only permits issuance of credential type: {}",
                delegation_id,
                joined_types
            );
        }

        true
    }
}