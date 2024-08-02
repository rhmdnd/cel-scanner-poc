go run main.go -i rules/platform/etcd-cert-file.yaml
go run main.go -i rules/platform/token-based-authentication-disabled.yaml
go run main.go -i rules/platform/scc-required-drop-capabilities.yaml
go run main.go -i rules/platform/image-provenance.yaml
go run main.go -i rules/platform/identity-provider-google.yaml
go run main.go -i rules/platform/identity-provider-configuration.yaml
go run main.go -i rules/platform/network-policy.yaml
