# cel-scanner-poc

The intention of this PoC is to explore how to write a compliance scanner for
OpenShift and Kubernetes based on [CEL](https://github.com/google/cel-spec).

The main use case is to use this implementation in the [Compliance
Operator](https://github.com/ComplianceAsCode/compliance-operator) as an
alternative to the `oscap` scanner, which is build on SCAP.

### Why would we want to explore this?

CEL is supported already in the Kubernetes ecosystem with admission
controllers, making it appealing for people looking to supply their own
compliance content. The SCAP standard and tooling is not suited to container
environments, and we need to work around those shortcomings in the Compliance
Operator.
