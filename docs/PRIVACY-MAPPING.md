# Privacy mapping

Mapping, not compliance: these rows show what the code checks on synthetic data. They are not legal advice or a compliance determination.

| regulation | article or section | what the article requires | what this repo does | evidence |
|---|---|---|---|---|
| GDPR | Art. 5(1)(c) | Personal data must be limited to what is necessary for the purpose. | Replaces each detected email, phone, SSN-shaped or Luhn-valid card match with a typed placeholder, scans again, and sends only the redacted text (R10, R11). It detects shapes, not purpose, so it does not decide what is necessary. | `test_redaction_uses_typed_placeholders_and_is_clean`, `test_pii_to_training_denied_and_to_clean_redacted`, `pii_redacted` |
| GDPR | Art. 5(1)(e) | Personal data must be kept no longer than necessary. | Denies confidential or secret data to a provider whose recorded zero_data_retention is false (R07) and rejects a registry entry where zero retention contradicts retention_days (R03). It reads the provider's recorded attribute and does not measure actual retention. | `test_confidential_to_non_zdr_denied`, `test_zdr_contradicting_retention_denied`, `confidential_to_non_zdr_deny` |
| GDPR | Art. 25 | Processing must be designed to protect data by default. | Any unknown provider, malformed request, invalid registry entry or unwritable evidence log ends in DENY, never ALLOW (R01, R02, R03). | `test_unknown_provider_denied`, `test_registry_shapes_fail_closed`, `test_malformed_requests_denied_not_crashed`, `test_unwritable_log_means_no_allow` |
| GDPR | Art. 28 | A processor must work under a binding contract with the controller. | Denies non-public data when the provider's recorded contract_signed is false (R08). It checks a yes/no flag, not the contract terms. | `test_internal_rules`, `no_contract_deny` |
| GDPR | Art. 30 | Records of processing must be kept. | Appends one hash-chained record per decision, including DENY, holding rule id, class counts and provider attributes; the verifier refuses an edited or reordered log. It is a per-decision log, not a full register of processing activities. | `test_clean_chain_verifies_and_links`, `test_edited_decision_refused`, `test_malformed_request_still_leaves_evidence` |
| GDPR | Art. 32 | Controllers and processors must apply security measures suited to the risk. | Detects AWS-key-shaped strings, private key headers, bearer tokens and high-entropy strings, then redacts them or denies the request (R07, R10). | `test_each_class_detected`, `test_secret_to_clean_provider_redacted`, `secrets_redacted_for_zdr` |
| GDPR | Art. 44 to 46 | Transfers of personal data outside the EU need a lawful basis or safeguards. | Denies non-public data to a provider whose recorded region is outside us and eu (R05). It checks the region label only, not the transfer mechanism. | `test_internal_rules`, `region_not_allowed_deny` |
| CCPA/CPRA | Cal. Civ. Code 1798.100(d) | A business must have a contract with a service provider or third party that receives personal information. | Denies non-public data when the provider's recorded contract_signed is false (R08). It checks a yes/no flag, not the contract terms. | `test_internal_rules`, `no_contract_deny` |
| CCPA/CPRA | Cal. Civ. Code 1798.81.5 | A business holding personal information must keep reasonable security procedures. | Keeps secret and PII values out of the evidence record and out of command output, and redacts them before they leave. | `test_records_hold_counts_not_values`, `test_stdout_never_contains_a_secret_value`, `test_secret_to_clean_provider_redacted` |

## Rows not mapped

- CCPA/CPRA 1798.100(c), collection and use reasonably necessary and proportionate: no test checks purpose or proportionality, so no row is claimed.
