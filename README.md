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


### What it takes to write Network Policy Check rule in OVAL:
The rule fetches all namespaces and network policies on the cluster and checks if 
each namespace contains at least one network policy. And also gives users the ability to
exclude certain namespace from the check.

```yaml
<def-group>
{{% set networkpolicies_api_path = '/apis/networking.k8s.io/v1/networkpolicies' %}}
{{% set namespaces_api_path = '/api/v1/namespaces' %}}
{{% set networkpolicies_for_non_ctlplane_namespaces_filter = '[.items[] | select((.metadata.namespace | startswith("openshift") | not) and (.metadata.namespace | startswith("kube-") | not) and .metadata.namespace != "default" and ({{if ne .var_network_policies_namespaces_exempt_regex "None"}}.metadata.namespace | test("{{.var_network_policies_namespaces_exempt_regex}}") | not{{else}}true{{end}})) | .metadata.namespace] | unique' %}}
{{% set non_ctlplane_namespaces_filter = '[.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default" and ({{if ne .var_network_policies_namespaces_exempt_regex "None"}}.metadata.name | test("{{.var_network_policies_namespaces_exempt_regex}}") | not{{else}}true{{end}}))]' %}}
  <definition class="compliance" id="configure_network_policies_namespaces" version="1">
    {{{ oval_metadata("Ensure that application Namespaces have Network Policies defined") }}}
    <criteria>
      <criterion comment="Make sure that the file '{{{ openshift_filtered_path(networkpolicies_api_path, networkpolicies_for_non_ctlplane_namespaces_filter) }}} exists."
                 test_ref="test_file_for_configure_network_policies_namespaces"/>
      <criterion comment="Make sure that the file '{{{ openshift_filtered_path(namespaces_api_path, non_ctlplane_namespaces_filter) }}}' exists."
                 test_ref="test_file_for_configure_network_policies_filtered_namespaces"/>
      <criteria operator="OR">
        <criterion comment="Make sure that all target elements exists for elements at path &#39;.items[:].spec.host&#39;"
        test_ref="test_elements_count_for_configure_network_policies_namespaces"/>
        <criteria operator="AND">
          <criterion comment="Make sure that there are no network policies in non-ctlplane namespaces"
          test_ref="test_configure_network_policies_namespaces"/>
          <criterion comment="Make sure that there are no namespaces in non-ctlplane namespaces"
          test_ref="test_configure_network_policies_filtered_namespaces"/>
        </criteria>
      </criteria>

    </criteria>
  </definition>

  <!-- OCP object file locations -->
  <local_variable id="configure_network_policies_namespaces_file_location" datatype="string"
                  comment="Path of file containing filtered non-ctlplane namespaces with network policies." version="1">
    <concat>
      <variable_component var_ref="ocp_data_root"/>
      <literal_component>{{{ openshift_filtered_path(networkpolicies_api_path, networkpolicies_for_non_ctlplane_namespaces_filter) }}}</literal_component>
    </concat>
  </local_variable>

  <local_variable id="configure_network_policies_filtered_namespaces_file_location" datatype="string"
                  comment="Path of file containing filtered non-ctlplane namespaces." version="1">
    <concat>
      <variable_component var_ref="ocp_data_root"/>
      <literal_component>{{{ openshift_filtered_path(namespaces_api_path, non_ctlplane_namespaces_filter) }}}</literal_component>
    </concat>
  </local_variable>

  <!-- File existence checks -->
  <unix:file_test id="test_file_for_configure_network_policies_namespaces" check="all" check_existence="only_one_exists"
    comment="Find the file to be checked ('{{{ openshift_filtered_path(networkpolicies_api_path, networkpolicies_for_non_ctlplane_namespaces_filter) }}}')." version="1">
    <unix:object object_ref="object_file_for_configure_network_policies_namespaces"/>
  </unix:file_test>

  <unix:file_object id="object_file_for_configure_network_policies_namespaces" version="1">
    <unix:filepath var_ref="configure_network_policies_namespaces_file_location"/>
  </unix:file_object>

  <unix:file_test id="test_file_for_configure_network_policies_filtered_namespaces" check="all" check_existence="only_one_exists"
    comment="Find the file to be checked ('{{{ openshift_filtered_path(namespaces_api_path, non_ctlplane_namespaces_filter) }}}')." version="1">
    <unix:object object_ref="object_file_for_configure_network_policies_filtered_namespaces"/>
  </unix:file_test>

  <unix:file_object id="object_file_for_configure_network_policies_filtered_namespaces" version="1">
    <unix:filepath var_ref="configure_network_policies_filtered_namespaces_file_location"/>
  </unix:file_object>

  <!-- Object gathering --> 
  <ind:yamlfilecontent_object id="object_configure_network_policies_namespaces" version="1">
    <ind:filepath var_ref="configure_network_policies_namespaces_file_location"/>
    <ind:yamlpath>[:]</ind:yamlpath>
  </ind:yamlfilecontent_object>
  <local_variable comment="Items counter" datatype="int" id="local_variable_counter_configure_network_policies_namespaces" version="1">
    <count>
      <object_component object_ref="object_configure_network_policies_namespaces" item_field="value" record_field="#"/>
    </count>
  </local_variable>

  <ind:yamlfilecontent_test id="test_configure_network_policies_namespaces" version="1" check="all" comment="Make sure there are no count for network policies in non-ctlplane namespaces" check_existence="none_exist" state_operator="AND">
    <ind:object object_ref="object_configure_network_policies_namespaces"/>
  </ind:yamlfilecontent_test>

  <ind:yamlfilecontent_object id="object_configure_network_policies_filtered_namespaces" version="1">
    <ind:filepath var_ref="configure_network_policies_filtered_namespaces_file_location"/>
    <ind:yamlpath>[:].metadata.name</ind:yamlpath>
  </ind:yamlfilecontent_object>
  <local_variable comment="Items counter control" datatype="int" id="local_variable_counter_configure_network_policies_filtered_namespaces" version="1">
    <count>
      <object_component object_ref="object_configure_network_policies_filtered_namespaces" item_field="value" record_field="#"/>
    </count>
  </local_variable>

  <ind:yamlfilecontent_test id="test_configure_network_policies_filtered_namespaces" version="1" check="all" comment="Make sure there are no count for namespaces in non-ctlplane namespaces" check_existence="none_exist" state_operator="AND">
    <ind:object object_ref="object_configure_network_policies_filtered_namespaces"/>
  </ind:yamlfilecontent_test>
  
  <!-- Object counts -->
  <ind:variable_test version="1" id="test_elements_count_for_configure_network_policies_namespaces" check="all"
    comment="Count elements at both paths and compare">
    <ind:object object_ref="object_elements_count_for_configure_network_policies_namespaces"/>
    <ind:state state_ref="state_elements_count_for_configure_network_policies_namespaces"/>
  </ind:variable_test>
  
  <ind:variable_object id="object_elements_count_for_configure_network_policies_namespaces" version="1">
    <ind:var_ref>local_variable_counter_configure_network_policies_namespaces</ind:var_ref>
  </ind:variable_object>

  <!-- Comparison -->
  <!-- This verifies that the filtered namespaces are equal to the namespaces with NetworkPolicies -->
  <ind:variable_state id="state_elements_count_for_configure_network_policies_namespaces" version="1">
    <ind:value datatype="int" var_ref="local_variable_counter_configure_network_policies_filtered_namespaces"/>
  </ind:variable_state>
  
  <!-- OCP data root declaration -->
  <external_variable comment="Root of OCP data dump" datatype="string" id="ocp_data_root" version="1" />
</def-group>
```


### Now let's compare it with CEL based Rule:
We use the inputs to reference api resources and tailored variables 
and then perform cel evaluation on it.
```yaml
kind: Rule
checkType: Platform
title: 'Ensure that application Namespaces have Network Policies defined.'
expression: >
  size(applicationNamespaces.items) == 0 || 
  size(
    applicationNamespaces.items
    .filter(ns, !ns.metadata.name.matches(excludedNamespaces.value))
    .filter(ns, networkPolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))
  ) == size(applicationNamespaces.items.filter(ns, !ns.metadata.name.matches(excludedNamespaces.value)))
inputs:
  - name: applicationNamespaces
    type: KubeGroupVersionResource
    apiGroup: ""
    version: v1
    resource: namespaces
  - name: networkPolicies
    type: KubeGroupVersionResource
    apiGroup: networking.k8s.io
    version: v1
    resource: networkpolicies
  - name: excludedNamespaces
    type: KubeGroupVersionResource
    apiGroup: compliance.openshift.io
    version: v1alpha1
    resource: variables
    subResource: ocp4-var-network-policies-namespaces-exempt-regex
    namespace: openshift-compliance
errorMessage: 'Application Namespaces do not have Network Policies defined.'
```



