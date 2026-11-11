package keystone.authz

import rego.v1

default allow := false
default allow_mortgage_action := false

allow if {
	input.principal.issuer == "keystone-agent"
	input.principal.subject == "keystone-mortgage-agent"
	input.principal.audience == "keystone-cra-gateway"
	input.principal.scopes == ["cra:credit-report:read"]
	input.action == "cra:get_credit_report"
	input.resource.tool == "get_credit_report"
	input.resource.arguments_valid == true
}

allow_mortgage_action if {
	input.principal.issuer == "keystone-agent"
	input.principal.subject == "keystone-mortgage-agent"
	input.principal.audience == "keystone-cra-gateway"
	input.principal.scopes == ["mortgage:assessment:request"]
	input.action == "mortgage:assess"
	input.resource.affordability_passed == true
	input.resource.is_standard_profile == true
	input.resource.adverse_credit_flags == 0
	is_number(input.resource.requested_loan_amount_gbp)
	input.resource.requested_loan_amount_gbp > 0
	input.resource.requested_loan_amount_gbp <= 500000
}
