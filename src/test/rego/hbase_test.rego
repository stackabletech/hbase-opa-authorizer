package hbase_test

import data.hbase

# Every fixture in allowed/ must produce allow=true under the real Rego policy.
test_all_allowed_inputs if {
	every key, fixture in data.fixtures.allowed {
		hbase.allow with input as fixture.input
	}
}

# Every fixture in denied/ must produce allow=false under the real Rego policy.
test_all_denied_inputs if {
	every key, fixture in data.fixtures.denied {
		not hbase.allow with input as fixture.input
	}
}
