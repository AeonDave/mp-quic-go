module github.com/AeonDave/mp-quic-go/integrationtests/upstream

go 1.26.0

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/AeonDave/mp-quic-go v0.0.0

require (
	github.com/quic-go/quic-go v0.63.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/AeonDave/mp-quic-go => ../..
