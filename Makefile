.PHONY: all test check build demo teardown clean

PYTHON ?= python3

all: check test

build:
	cd rust && cargo build --workspace --locked

check:
	$(PYTHON) -c 'from bench import q2; assert q2.verify_contract()==[], "q2 contract drift"'
	cd rust && cargo fmt --all --check
	cd rust && cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'
	$(PYTHON) tests/fuzz_reference.py
	$(PYTHON) -m unittest discover -s tests -p 'test_session.py'
	$(PYTHON) tests/fuzz_session.py
	$(PYTHON) -m unittest discover -s tests -p 'test_mobility.py'
	$(PYTHON) tests/fuzz_mobility.py
	$(PYTHON) tests/fuzz_redundant.py
	$(PYTHON) tests/fuzz_redundant_state.py
	cd rust && cargo test --workspace --all-targets --locked

demo:
	@echo "=== R8 15-minute isolated netns demonstration ==="
	@bash -c '\
		trap "bash tools/netns-topo.sh teardown >/dev/null 2>&1 || true" EXIT;\
		bash tools/netns-topo.sh teardown >/dev/null 2>&1 || true;\
		bash tools/netns-topo.sh setup && \
		bash tools/netns-topo.sh demo && \
		echo "=== Demo completed successfully ==="'

teardown:
	bash tools/netns-topo.sh teardown

clean: teardown
	rm -rf rust/target
