#![no_std]

mod storage;
mod structures;
mod helpers;

multiversx_sc::imports!();
use multiversx_sc::codec::TopDecode;
use crate::structures::*;


fn decode_credential_id<M: ManagedTypeApi>(buffer: ManagedBuffer<M>) -> u64 {
    let decoded_id: u64 = TopDecode::top_decode(buffer).unwrap();
    decoded_id
}

#[multiversx_sc::contract]
pub trait DigitalIdentityContract:
    storage::StorageModule+
    helpers::HelpersModule
{
    #[init]
    fn init(&self) {
        self.admin().set(&self.blockchain().get_caller());
        self.set_paused(false);
    }

    // DID Management
    #[endpoint(createDid)]
    fn create_did(
        &self,
        verification_method: VerificationMethod<Self::Api>,
        services: ManagedVec<Service<Self::Api>>,
    ) {
        require!(!self.is_paused(), "Contract is paused");

        let caller = self.blockchain().get_caller();
        let timestamp = self.blockchain().get_block_timestamp();

        let did = self.generate_did(&caller);
        require!(self.did_documents(&did).is_empty(), "DID already exists");

        let mut auth_methods = ManagedVec::new();
        auth_methods.push(verification_method.id.clone());

        let document = DidDocument {
            did: did.clone(),
            controller: caller.clone(),
            verification_methods: ManagedVec::from_single_item(verification_method),
            authentication: auth_methods,
            assertion_method: ManagedVec::new(),
            key_agreement: ManagedVec::new(),
            service_endpoints: services,
            created: timestamp,
            updated: timestamp,
        };

        self.did_documents(&did).set(&document);
        self.address_to_did(&caller).set(&did);
    }

    // Schema Management
    #[endpoint(registerSchema)]
    fn register_schema(
        &self,
        type_: ManagedBuffer,
        attributes: ManagedVec<SchemaAttribute<Self::Api>>,
        version: ManagedBuffer,
    ) {
        require!(!self.is_paused(), "Contract is paused");
        let caller = self.blockchain().get_caller();
        require!(
            !self.issuers(&caller).is_empty(),
            "Only registered issuers can create schemas"
        );

        let schema_id = self.generate_schema_id(&type_, &version);
        require!(
            self.credential_schemas(&schema_id).is_empty(),
            "Schema already exists"
        );

        let schema = CredentialSchema {
            id: schema_id.clone(),
            type_,
            attributes,
            issuer: caller,
            version,
        };

        self.credential_schemas(&schema_id).set(&schema);
    }

    // Credential Management
    #[endpoint(issueCredential)]
    fn issue_credential(
        &self,
        holder: ManagedAddress,
        credential_type: ManagedVec<ManagedBuffer>,
        schema_id: ManagedBuffer,
        claims: Claims<Self::Api>,
        expiration_date: Option<u64>,
        encryption_key: ManagedBuffer,
    ) {
        require!(!self.is_paused(), "Contract is paused");
        let caller = self.blockchain().get_caller();
        require!(
            !self.issuers(&caller).is_empty(),
            "Only registered issuers can issue credentials"
        );

        // Validate schema
        let schema = self.credential_schemas(&schema_id).get();
        self.validate_claims_against_schema(&claims, &schema);

        let timestamp = self.blockchain().get_block_timestamp();
        let credential_id = self.generate_credential_id();

        let proof = self.generate_credential_proof(
            &caller,
            &holder,
            claims.merkle_root.clone(),
            timestamp,
        );

        let credential = Credential {
            id: self.managed_buffer_from_bytes(credential_id.to_boxed_bytes().as_ref()),
            issuer: caller,
            holder: holder.clone(),
            credential_type,
            schema_id,
            content_hash: claims.merkle_root.clone(),
            claims,
            issuance_date: timestamp,
            expiration_date,
            revoked: false,
            delegation_id: None,
            encryption_key,
            proof,
        };
        let credential_id_u64 = decode_credential_id(credential_id);

        self.credentials(&credential_id_u64).set(&credential);
        self.holder_credentials(&holder).push(&credential_id_u64);
    }

    // Delegation
    #[endpoint(delegateCredentialIssuance)]
    fn delegate_credential_issuance(
        &self,
        delegate: ManagedAddress,
        credential_types: ManagedVec<ManagedBuffer>,
        valid_until: u64,
    ) {
        require!(!self.is_paused(), "Contract is paused");
        let caller = self.blockchain().get_caller();
        require!(
            !self.issuers(&caller).is_empty(),
            "Only registered issuers can delegate"
        );

        let delegation_id = self.next_delegation_id().get();
        let delegation = Delegation {
            id: delegation_id,
            delegator: caller,
            delegate: delegate.clone(),
            credential_types,
            valid_until,
            revoked: false,
        };

        self.delegations(&delegation_id).set(&delegation);
        self.delegate_to_delegations(&delegate).push(&delegation_id);
        self.next_delegation_id().set(delegation_id + 1);
    }

    // GDPR Compliance
    #[endpoint(requestDataDeletion)]
    fn request_data_deletion(&self) {
        let caller = self.blockchain().get_caller();
        require!(
            !self.holder_credentials(&caller).is_empty(),
            "No credentials found for holder"
        );

        // Mark credentials for deletion
        let holder_credentials = self.holder_credentials(&caller); // Bind the VecMapper to a variable
        let credentials = holder_credentials.iter();
        for credential_id in credentials {
            self.mark_credential_for_deletion(credential_id);
        }

        // Emit event for off-chain deletion of associated data
        self.data_deletion_requested_event(&caller);
    }

    #[endpoint(markCredentialForDeletion)]
    fn mark_credential_for_deletion(
        &self,
        credential_id: u64,
    ) {
        // Fetch the credential from storage
        let mut credential = self.credentials(&credential_id).get();

        // Check if the credential is already revoked or marked for deletion
        require!(
        !credential.revoked,
        "Credential is already revoked or marked for deletion"
    );

        // Mark the credential as revoked
        credential.revoked = true;

        // Update the credential in storage
        self.credentials(&credential_id).set(&credential);

        // Emit an event for deletion
        self.credential_marked_for_deletion_event(credential_id);
    }

    // Events
    #[event("credentialMarkedForDeletion")]
    fn credential_marked_for_deletion_event(
        &self,
        #[indexed] credential_id: u64,
    );

    #[event("dataDeleteRequested")]
    fn data_deletion_requested_event(&self, #[indexed] holder: &ManagedAddress);

    #[inline]
    fn is_paused(&self) -> bool {
        self.paused().get()
    }

    #[only_owner]
    #[endpoint(setPaused)]
    fn set_paused(&self, paused: bool) {
        self.paused().set(paused);
    }
}