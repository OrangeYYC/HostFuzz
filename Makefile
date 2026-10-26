IMAGE ?= hostfuzz
OUTPUTS ?= $(CURDIR)/outputs

.PHONY: build build-full list demo replay reproduce-rq1 reproduce-rq3 clean

build:
	docker build -t $(IMAGE) .

build-full:
	docker build --target full -t $(IMAGE):full .

list: build
	mkdir -p $(OUTPUTS)
	./scripts/hostfuzz-docker.sh list

demo: build
	mkdir -p $(OUTPUTS)
	./scripts/hostfuzz-docker.sh run \
		--case 01_btstack_sm_pairing_central --seconds 120

replay: build
	mkdir -p $(OUTPUTS)
	@if [ -z "$(INPUT)" ]; then \
		echo "usage: make replay INPUT=/outputs/<run>/fuzz-<timestamp>/queue/<input>" >&2; \
		exit 1; \
	fi
	./scripts/hostfuzz-docker.sh replay --case 01_btstack_sm_pairing_central --input "$(INPUT)"

reproduce-rq1:
	python3 experiments/run_rq1.py --duration 120

reproduce-rq3:
	python3 experiments/run_rq3.py --duration 120

clean:
	rm -rf outputs
