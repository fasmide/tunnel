.PHONY: test conformance vet fuzz

test:
	go test -race -shuffle=on -count=1 -timeout=180s ./...

conformance:
	go test -race -run 'Conformance|Private|Trust|Bootstrap|ConstrainedCA|InvalidDomains|ExistingEd25519|AdminSocket|HelloHandler|JoinServeModes' -count=10 -timeout=180s ./...

vet:
	go vet ./...

fuzz:
	go test ./internal/wire -run '^$$' -fuzz FuzzReadFrame -fuzztime=10s -parallel=2
	go test ./internal/server -run '^$$' -fuzz FuzzPeekSNI -fuzztime=10s -parallel=2
	go test ./internal/server -run '^$$' -fuzz FuzzPublicHTTPHeader -fuzztime=10s -parallel=2
