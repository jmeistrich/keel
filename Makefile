.PHONY: build proto testdata wasm test testpretty

# Supply PACKAGES arg to only run tests for one page e.g. PACKAGES=./traing
PACKAGES?=./...

# Supply RUN to only run some tests e.g. `RUN=TestMyFunction make test`
RUNARG=
ifdef RUN
# If running only some tests add -v for more verbose output
RUNARG=-run $(RUN) -v
endif

build:
	export CGO_ENABLED=0 && go build -o ./bin/keel cmd/keel/main.go

proto:
	nix-shell --command "protoc -I . \
		--go_out=. \
		--go_opt=paths=source_relative \
		proto/schema.proto"

testdata:
	nix-shell --command "cd ./schema && go run ./tools/generate_testdata.go ./testdata"

test:
	go test $(PACKAGES) -count=1 $(RUNARG)

test-js:
	cd ./packages/functions-runtime && pnpm run test
	cd ./packages/testing-runtime && pnpm run test
	cd ./packages/wasm && pnpm run test

lint:
	export CGO_ENABLED=0 && golangci-lint run  -c .golangci.yml

wasm:
	mkdir -p ./packages/wasm/dist
	GOOS=js GOARCH=wasm go build -o ./packages/wasm/dist/keel.wasm ./packages/wasm/lib/main.go
	node ./packages/wasm/encodeWasm.js

prettier:
	npx prettier --write './integration/**/*.{ts,json,yaml}'
	npx prettier --write './packages/**/*.{ts,js}'

install:
	go mod download
	npm install
	cd ./packages/functions-runtime && pnpm install
	cd ./packages/testing-runtime && pnpm install
	cd ./packages/wasm && pnpm install

setup-conventional-commits:
	brew install pre-commit -q
	pre-commit install --hook-type commit-msg

goreleaser:
	rm -rf dist
	goreleaser release --snapshot

rpcApi:
	protoc \
			--go_opt=Mschema.proto=github.com/teamkeel/keel/proto \
			--twirp_out=Mschema.proto=github.com/teamkeel/keel/proto:. \
			--go_out=./ rpc/rpc.proto