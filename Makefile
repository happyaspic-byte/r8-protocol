.PHONY: all test check build demo teardown clean compare-smoke package-deb repro-bundle

PYTHON ?= python3

all: check test

build:
	cd rust && cargo build --workspace --locked

check:
	$(PYTHON) -c 'from bench import q2; assert q2.verify_contract()==[], "q2 contract drift"'
	test -z "$$(gofmt -l .)"
	go vet ./...
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
	go test ./...
	cd rust && cargo test --workspace --all-targets --locked

package-deb:
	cd rust && cargo build --release --locked -p r8d --bin r8d -p r8ping --bin r8ping
	rm -rf .tmp-deb
	mkdir -p .tmp-deb/DEBIAN .tmp-deb/usr/bin .tmp-deb/usr/lib/r8-protocol .tmp-deb/usr/lib/systemd/system .tmp-deb/usr/share/doc/r8-protocol dist
	cp packaging/debian/DEBIAN/control .tmp-deb/DEBIAN/control
	cp packaging/debian/lib/systemd/system/r8d.service .tmp-deb/usr/lib/systemd/system/r8d.service
	cp rust/target/release/r8d rust/target/release/r8ping .tmp-deb/usr/bin/
	cp packaging/debian/r8gateway .tmp-deb/usr/bin/r8gateway
	cp reference/r8ref.py reference/r8gateway.py reference/r8sdk.py .tmp-deb/usr/lib/r8-protocol/
	cp LICENSE .tmp-deb/usr/share/doc/r8-protocol/copyright
	chmod 755 .tmp-deb/usr/bin/r8d .tmp-deb/usr/bin/r8ping .tmp-deb/usr/bin/r8gateway
	dpkg-deb --root-owner-group --build .tmp-deb dist/r8-protocol_0.1.0_amd64.deb
	rm -rf .tmp-deb

compare-smoke:
	$(PYTHON) -c 'import pathlib, shutil; from bench.compare import run, validate; out=pathlib.Path(".tmp-compare-smoke"); shutil.rmtree(out, ignore_errors=True); assert run.run_package(out, smoke=True)==0; assert validate.validate_package(out)==[]; shutil.rmtree(out)'

repro-bundle:
	$(PYTHON) bench/repro.py --output .tmp-repro.json

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
