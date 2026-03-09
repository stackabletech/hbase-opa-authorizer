package hbase_test

import data.hbase

# Every fixture in allowed must produce allow=true under the real Rego policy.
test_all_allowed_inputs if {
	print("allowed fixtures:", count(data.fixtures.allowed))
	every fixture in data.fixtures.allowed {
		hbase.allow with input as fixture.input
	}
}

# Every fixture in denied must produce allow=false under the real Rego policy.
test_all_denied_inputs if {
	print("denied fixtures:", count(data.fixtures.denied))
	every fixture in data.fixtures.denied {
		not hbase.allow with input as fixture.input
	}
}
