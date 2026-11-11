package keystone.authz

import rego.v1

valid_input := {
	"principal": {
		"issuer": "keystone-agent",
		"subject": "keystone-mortgage-agent",
		"audience": "keystone-cra-gateway",
		"scopes": ["cra:credit-report:read"],
	},
	"action": "cra:get_credit_report",
	"resource": {
		"tool": "get_credit_report",
		"arguments_valid": true,
	},
}

test_allows_authorized_credit_read if {
	allow with input as valid_input
}

test_denies_missing_scope if {
	not allow with input as object.union(valid_input, {
		"principal": {
			"issuer": "keystone-agent",
			"subject": "keystone-mortgage-agent",
			"audience": "keystone-cra-gateway",
			"scopes": [],
		},
	})
}

test_denies_additional_scopes if {
	not allow with input as object.union(valid_input, {
		"principal": {
			"issuer": "keystone-agent",
			"subject": "keystone-mortgage-agent",
			"audience": "keystone-cra-gateway",
			"scopes": ["cra:credit-report:read", "cra:identity:verify"],
		},
	})
}

test_denies_wrong_action if {
	not allow with input as object.union(valid_input, {
		"action": "cra:identity:verify",
	})
}

test_denies_invalid_arguments if {
	not allow with input as object.union(valid_input, {
		"resource": {
			"tool": "get_credit_report",
			"arguments_valid": false,
		},
	})
}

test_denies_unknown_identity if {
	not allow with input as object.union(valid_input, {
		"principal": {
			"issuer": "untrusted-issuer",
			"subject": "keystone-mortgage-agent",
			"audience": "keystone-cra-gateway",
			"scopes": ["cra:credit-report:read"],
		},
	})
}

mortgage_action_input := {
	"principal": {
		"issuer": "keystone-agent",
		"subject": "keystone-mortgage-agent",
		"audience": "keystone-cra-gateway",
		"scopes": ["mortgage:assessment:request"],
	},
	"action": "mortgage:assess",
	"resource": {
		"requested_loan_amount_gbp": 400000,
		"affordability_passed": true,
		"is_standard_profile": true,
		"adverse_credit_flags": 0,
	},
}

test_allows_standard_assessment_below_mandate_cap if {
	allow_mortgage_action with input as mortgage_action_input
}

test_denies_mortgage_assessment_without_action_scope if {
	not allow_mortgage_action with input as object.union(mortgage_action_input, {
		"principal": {
			"issuer": "keystone-agent",
			"subject": "keystone-mortgage-agent",
			"audience": "keystone-cra-gateway",
			"scopes": ["cra:credit-report:read"],
		},
	})
}

test_denies_assessment_above_mandate_cap if {
	not allow_mortgage_action with input as object.union(mortgage_action_input, {
		"resource": {
			"requested_loan_amount_gbp": 2000000,
			"affordability_passed": true,
			"is_standard_profile": true,
			"adverse_credit_flags": 0,
		},
	})
}

test_denies_nonstandard_or_adverse_profiles if {
	not allow_mortgage_action with input as object.union(mortgage_action_input, {
		"resource": {
			"requested_loan_amount_gbp": 200000,
			"affordability_passed": true,
			"is_standard_profile": false,
			"adverse_credit_flags": 0,
		},
	})
	not allow_mortgage_action with input as object.union(mortgage_action_input, {
		"resource": {
			"requested_loan_amount_gbp": 200000,
			"affordability_passed": true,
			"is_standard_profile": true,
			"adverse_credit_flags": 1,
		},
	})
}
