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

#### What we do today

Today, we implement checks using
[SCAP](https://csrc.nist.gov/projects/security-content-automation-protocol) and
[OVAL](https://oval.mitre.org/), which are fed into a tool called `oscap` to
evaluate RHCOS and OpenShift. The
[OpenSCAP](https://github.com/OpenSCAP/openscap) tool, called `oscap`,
implements SCAP and OVAL, and accepts SCAP "datastreams" as an argument (e.g.,
`oscap oval eval --datastream-id ds.xml ...`).

This is ultimately the vehicle we're using to evaluate compliance posture for
OpenShift via the Compliance Operator.

The following is the OVAL we need to check if OpenShift has an identity
provider configured:

```xml
<?xml version='1.0' encoding='utf-8'?>
<oval-def:oval_definitions xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <oval-def:generator>
    <oval:product_name>OVALFileLinker from SCAP Security Guide</oval:product_name>
    <oval:product_version>ssg: [0, 1, 75], python: 3.12.3</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2024-08-02T12:58:54</oval:timestamp>
  </oval-def:generator>
  <oval-def:definitions>
    <oval-def:definition id="oval:ssg-idp_is_configured:def:1" version="1" class="compliance">
      <oval-def:metadata>
        <oval-def:title>Configure An Identity Provider</oval-def:title>
        <oval-def:affected family="unix">
          <oval-def:platform>Red Hat OpenShift Container Platform 4</oval-def:platform>
        </oval-def:affected>
        <oval-def:reference ref_id="CCE-84088-4" source="CCE" />
        <oval-def:reference ref_id="idp_is_configured" source="ssg" />
        <oval-def:description>In the YAML/JSON file '/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e' at path '.identityProviders[:].type' at least one: value equals '.*'</oval-def:description>
      </oval-def:metadata>
      <oval-def:criteria operator="AND">
        <oval-def:criterion comment="In the YAML/JSON file '/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e' at path '.identityProviders[:].type' at least one" test_ref="oval:ssg-test_idp_is_configured:tst:1" />
        <oval-def:criterion comment="Make sure that the file '/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e' exists." test_ref="oval:ssg-test_file_for_idp_is_configured:tst:1" />
      </oval-def:criteria>
    </oval-def:definition>
  </oval-def:definitions>
  <oval-def:tests>
    <ind:yamlfilecontent_test id="oval:ssg-test_idp_is_configured:tst:1" version="1" check="all" comment="In the file '/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e' find only one object at path '.identityProviders[:].type'." check_existence="only_one_exists" state_operator="AND">
      <ind:object object_ref="oval:ssg-object_idp_is_configured:obj:1" />
      <ind:state state_ref="oval:ssg-state_idp_is_configured:ste:1" />
    </ind:yamlfilecontent_test>
    <unix:file_test id="oval:ssg-test_file_for_idp_is_configured:tst:1" version="1" check="all" comment="Find the file to be checked ('/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e')." check_existence="only_one_exists" state_operator="AND">
      <unix:object object_ref="oval:ssg-object_file_for_idp_is_configured:obj:1" />
    </unix:file_test>
  </oval-def:tests>
  <oval-def:objects>
    <unix:file_object id="oval:ssg-object_file_for_idp_is_configured:obj:1" version="1">
      <unix:filepath var_ref="oval:ssg-idp_is_configured_file_location:var:1" />
    </unix:file_object>
    <ind:yamlfilecontent_object id="oval:ssg-object_idp_is_configured:obj:1" version="1">
      <ind:filepath var_ref="oval:ssg-idp_is_configured_file_location:var:1" />
      <ind:yamlpath>.identityProviders[:].type</ind:yamlpath>
    </ind:yamlfilecontent_object>
  </oval-def:objects>
  <oval-def:states>
    <ind:yamlfilecontent_state id="oval:ssg-state_idp_is_configured:ste:1" version="1" operator="AND">
      <ind:value datatype="record" entity_check="at least one">
        <oval-def:field name="#" operation="pattern match">.*</oval-def:field>
      </ind:value>
    </ind:yamlfilecontent_state>
  </oval-def:states>
  <oval-def:variables>
    <oval-def:external_variable id="oval:ssg-ocp_data_root:var:1" version="1" datatype="string" comment="Root of OCP data dump" />
    <oval-def:local_variable id="oval:ssg-idp_is_configured_file_location:var:1" version="1" datatype="string" comment="The actual path of the file to scan.">
      <oval-def:concat>
        <oval-def:variable_component var_ref="oval:ssg-ocp_data_root:var:1" />
        <oval-def:literal_component>/apis/config.openshift.io/v1/oauths/cluster#489c53adb0325a207f2120d4dee0ef775dad56dceaa74bafc10bf32c1da46e9e</oval-def:literal_component>
      </oval-def:concat>
    </oval-def:local_variable>
  </oval-def:variables>
</oval-def:oval_definitions>
```

Or checking if the `kubeadmin` user has been removed:

```xml
<?xml version='1.0' encoding='utf-8'?>
<oval-def:oval_definitions xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <oval-def:generator>
    <oval:product_name>OVALFileLinker from SCAP Security Guide</oval:product_name>
    <oval:product_version>ssg: [0, 1, 75], python: 3.12.3</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2024-08-02T12:58:54</oval:timestamp>
  </oval-def:generator>
  <oval-def:definitions>
    <oval-def:definition id="oval:ssg-kubeadmin_removed:def:1" version="1" class="compliance">
      <oval-def:metadata>
        <oval-def:title>Ensure that the kubeadmin secret has been removed</oval-def:title>
        <oval-def:affected family="unix">
          <oval-def:platform>Red Hat OpenShift Container Platform 4</oval-def:platform>
        </oval-def:affected>
        <oval-def:reference ref_id="CCE-90387-2" source="CCE" />
        <oval-def:reference ref_id="kubeadmin_removed" source="ssg" />
        <oval-def:description>In the Compliance Operator-generated file '/api/v1/namespaces/kube-system/secrets/kubeadmin' the `not found` annotation should be set</oval-def:description>
      </oval-def:metadata>
      <oval-def:criteria operator="AND">
        <oval-def:criterion comment="In the Compliance Operator-generated file '/api/v1/namespaces/kube-system/secrets/kubeadmin' the `not found` annotation should be set" test_ref="oval:ssg-test_kubeadmin_removed:tst:1" />
        <oval-def:criterion comment="Make sure that the file '/api/v1/namespaces/kube-system/secrets/kubeadmin' exists." test_ref="oval:ssg-test_file_for_kubeadmin_removed:tst:1" />
      </oval-def:criteria>
    </oval-def:definition>
  </oval-def:definitions>
  <oval-def:tests>
    <ind:textfilecontent54_test id="oval:ssg-test_kubeadmin_removed:tst:1" version="1" check="all" comment="tests the presence of '# kube-api-error=NotFound' setting in the /api/v1/namespaces/kube-system/secrets/kubeadmin file" state_operator="AND">
      <ind:object object_ref="oval:ssg-obj_kubeadmin_removed:obj:1" />
    </ind:textfilecontent54_test>
    <unix:file_test id="oval:ssg-test_file_for_kubeadmin_removed:tst:1" version="1" check="all" comment="Find the file to be checked ('/api/v1/namespaces/kube-system/secrets/kubeadmin')." check_existence="only_one_exists" state_operator="AND">
      <unix:object object_ref="oval:ssg-object_file_for_kubeadmin_removed:obj:1" />
    </unix:file_test>
  </oval-def:tests>
  <oval-def:objects>
    <ind:textfilecontent54_object id="oval:ssg-obj_kubeadmin_removed:obj:1" version="1">
      <ind:filepath var_ref="oval:ssg-kubeadmin_removed_file_location:var:1" />
      <ind:pattern operation="pattern match"># kube-api-error=NotFound</ind:pattern>
      <ind:instance operation="greater than or equal" datatype="int">1</ind:instance>
    </ind:textfilecontent54_object>
    <unix:file_object id="oval:ssg-object_file_for_kubeadmin_removed:obj:1" version="1">
      <unix:filepath var_ref="oval:ssg-kubeadmin_removed_file_location:var:1" />
    </unix:file_object>
  </oval-def:objects>
  <oval-def:variables>
    <oval-def:external_variable id="oval:ssg-ocp_data_root:var:1" version="1" datatype="string" comment="Root of OCP data dump" />
    <oval-def:local_variable id="oval:ssg-kubeadmin_removed_file_location:var:1" version="1" datatype="string" comment="The actual path of the file to scan.">
      <oval-def:concat>
        <oval-def:variable_component var_ref="oval:ssg-ocp_data_root:var:1" />
        <oval-def:literal_component>/api/v1/namespaces/kube-system/secrets/kubeadmin</oval-def:literal_component>
      </oval-def:concat>
    </oval-def:local_variable>
  </oval-def:variables>
</oval-def:oval_definitions>%
```

Let's look at a more complicated example where we want to check that the
OpenShift API server is configured in a specific way:

```xml
<?xml version='1.0' encoding='utf-8'?>
<oval-def:oval_definitions xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <oval-def:generator>
    <oval:product_name>OVALFileLinker from SCAP Security Guide</oval:product_name>
    <oval:product_version>ssg: [0, 1, 75], python: 3.12.3</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2024-08-02T12:58:54</oval:timestamp>
  </oval-def:generator>
  <oval-def:definitions>
    <oval-def:definition id="oval:ssg-api_server_token_auth:def:1" version="1" class="compliance">
      <oval-def:metadata>
        <oval-def:title>Disable Token-based Authentication</oval-def:title>
        <oval-def:affected family="unix">
          <oval-def:platform>Red Hat OpenShift Container Platform 4</oval-def:platform>
        </oval-def:affected>
        <oval-def:reference ref_id="CCE-83481-2" source="CCE" />
        <oval-def:reference ref_id="api_server_token_auth" source="ssg" />
        <oval-def:description>In the YAML/JSON file '/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145' at path '.apiServerArguments["enable-admission-plugins"][:]' all: value equals '^token-auth-file$'</oval-def:description>
      </oval-def:metadata>
      <oval-def:criteria operator="AND">
        <oval-def:criterion comment="In the YAML/JSON file '/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145' at path '.apiServerArguments[&quot;enable-admission-plugins&quot;][:]' all" test_ref="oval:ssg-test_api_server_token_auth:tst:1" />
        <oval-def:criterion comment="Make sure that the file '/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145' exists." test_ref="oval:ssg-test_file_for_api_server_token_auth:tst:1" />
      </oval-def:criteria>
    </oval-def:definition>
  </oval-def:definitions>
  <oval-def:tests>
    <ind:yamlfilecontent_test id="oval:ssg-test_api_server_token_auth:tst:1" version="1" check="all" comment="In the file '/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145' find only one object at path '.apiServerArguments[&quot;enable-admission-plugins&quot;][:]'." check_existence="none_exist" state_operator="AND">
      <ind:object object_ref="oval:ssg-object_api_server_token_auth:obj:1" />
    </ind:yamlfilecontent_test>
    <unix:file_test id="oval:ssg-test_file_for_api_server_token_auth:tst:1" version="1" check="all" comment="Find the file to be checked ('/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145')." check_existence="only_one_exists" state_operator="AND">
      <unix:object object_ref="oval:ssg-object_file_for_api_server_token_auth:obj:1" />
    </unix:file_test>
  </oval-def:tests>
  <oval-def:objects>
    <unix:file_object id="oval:ssg-object_file_for_api_server_token_auth:obj:1" version="1">
      <unix:filepath var_ref="oval:ssg-api_server_token_auth_file_location:var:1" />
    </unix:file_object>
    <ind:yamlfilecontent_object id="oval:ssg-object_api_server_token_auth:obj:1" version="1">
      <ind:filepath var_ref="oval:ssg-api_server_token_auth_file_location:var:1" />
      <ind:yamlpath>.apiServerArguments["enable-admission-plugins"][:]</ind:yamlpath>
    </ind:yamlfilecontent_object>
  </oval-def:objects>
  <oval-def:variables>
    <oval-def:external_variable id="oval:ssg-ocp_data_root:var:1" version="1" datatype="string" comment="Root of OCP data dump" />
    <oval-def:local_variable id="oval:ssg-api_server_token_auth_file_location:var:1" version="1" datatype="string" comment="The actual path of the file to scan.">
      <oval-def:concat>
        <oval-def:variable_component var_ref="oval:ssg-ocp_data_root:var:1" />
        <oval-def:literal_component>/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145</oval-def:literal_component>
      </oval-def:concat>
    </oval-def:local_variable>
  </oval-def:variables>
</oval-def:oval_definitions>
```

All three examples above rely on fetching information about the cluster, like
users, secrets, and a `ConfigMap`. But, those details aren't defined in the
OVAL. How does the operator know where to get those resources? :thinking:


The API paths used to fetch the resources we need are stuffed into a separate
part of the datastream, outside the OVAL snippets above. These details are
hiding in plain sight within the standard, and fished out by the operator
later. When the operator fetches these resources, it saves them as YAML in a
file and passes them to the `oscap` scanner.

```xml
<html:li>
  <html:code class="ocp-api-endpoint" id="ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145">{{if ne .hypershift_cluster "None"}}/api/v1/namespaces/{{.hypershift_namespace_prefix}}-{{.hypershift_cluster}}/configmaps/kas-config{{else}}/api/v1/namespaces/openshift-kube-apiserver/configmaps/config{{end}}</html:code>
  API endpoint, filter with with the <html:code>jq</html:code> utility using the following filter
  <html:code class="ocp-api-filter" id="filter-ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145">{{if ne .hypershift_cluster "None"}}[.data."config.json" | fromjson]{{else}}[.data."config.yaml" | fromjson]{{end}}</html:code>
  and persist it to the local
  <html:code class="ocp-dump-location" id="dump-ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145">
    <xccdf-1.2:sub idref="xccdf_org.ssgproject.content_value_ocp_data_root" use="legacy" />/api/v1/namespaces/openshift-kube-apiserver/configmaps/config#ffe65d9fac11909686e59349c6a0111aaf57caa26bd2db3e7dcb1a0a22899145</html:code>
  file.
</html:li>
```

The `oscap` scanner is just checking that the YAML within a particular file
matches the criteria modeled in the OVAL.

An even more complicated case is when we need to check that each namespace has
a network policy configured. For this, we need to interact with the OVAL
directly in the rule. We don't have tooling to abstract away the complexity,
and we also need to account for excluded namespaces (e.g., anything in
`kube-*`).

That usecase manifests in the following OVAL:

```xml
<?xml version='1.0' encoding='utf-8'?>
<oval-def:oval_definitions xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd  http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">
  <oval-def:generator>
    <oval:product_name>OVALFileLinker from SCAP Security Guide</oval:product_name>
    <oval:product_version>ssg: [0, 1, 75], python: 3.12.3</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2024-08-02T12:58:54</oval:timestamp>
  </oval-def:generator>
  <oval-def:definitions>
    <oval-def:definition id="oval:ssg-configure_network_policies_namespaces:def:1" version="1" class="compliance">
      <oval-def:metadata>
        <oval-def:title>Ensure that application Namespaces have Network Policies defined.</oval-def:title>
        <oval-def:affected family="unix">
          <oval-def:platform>Red Hat OpenShift Container Platform 4</oval-def:platform>
        </oval-def:affected>
        <oval-def:reference ref_id="configure_network_policies_namespaces" source="ssg" />
        <oval-def:description>Ensure that application Namespaces have Network Policies defined</oval-def:description>
      </oval-def:metadata>
      <oval-def:criteria operator="AND">
        <oval-def:criterion comment="Make sure that the file '/apis/networking.k8s.io/v1/networkpolicies#7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f exists." test_ref="oval:ssg-test_file_for_configure_network_policies_namespaces:tst:1" />
        <oval-def:criterion comment="Make sure that the file '/api/v1/namespaces#f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2' exists." test_ref="oval:ssg-test_file_for_configure_network_policies_filtered_namespaces:tst:1" />
        <oval-def:criteria operator="OR">
          <oval-def:criterion comment="Make sure that all target elements exists for elements at path '.items[:].spec.host'" test_ref="oval:ssg-test_elements_count_for_configure_network_policies_namespaces:tst:1" />
          <oval-def:criteria operator="AND">
            <oval-def:criterion comment="Make sure that there are no network policies in non-ctlplane namespaces" test_ref="oval:ssg-test_configure_network_policies_namespaces:tst:1" />
            <oval-def:criterion comment="Make sure that there are no namespaces in non-ctlplane namespaces" test_ref="oval:ssg-test_configure_network_policies_filtered_namespaces:tst:1" />
          </oval-def:criteria>
        </oval-def:criteria>
      </oval-def:criteria>
    </oval-def:definition>
  </oval-def:definitions>
  <oval-def:tests>
    <unix:file_test id="oval:ssg-test_file_for_configure_network_policies_namespaces:tst:1" version="1" check="all" comment="Find the file to be checked ('/apis/networking.k8s.io/v1/networkpolicies#7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f')." check_existence="only_one_exists" state_operator="AND">
      <unix:object object_ref="oval:ssg-object_file_for_configure_network_policies_namespaces:obj:1" />
    </unix:file_test>
    <unix:file_test id="oval:ssg-test_file_for_configure_network_policies_filtered_namespaces:tst:1" version="1" check="all" comment="Find the file to be checked ('/api/v1/namespaces#f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2')." check_existence="only_one_exists" state_operator="AND">
      <unix:object object_ref="oval:ssg-object_file_for_configure_network_policies_filtered_namespaces:obj:1" />
    </unix:file_test>
    <ind:yamlfilecontent_test id="oval:ssg-test_configure_network_policies_namespaces:tst:1" version="1" check="all" comment="Make sure there are no count for network policies in non-ctlplane namespaces" check_existence="none_exist" state_operator="AND">
      <ind:object object_ref="oval:ssg-object_configure_network_policies_namespaces:obj:1" />
    </ind:yamlfilecontent_test>
    <ind:yamlfilecontent_test id="oval:ssg-test_configure_network_policies_filtered_namespaces:tst:1" version="1" check="all" comment="Make sure there are no count for namespaces in non-ctlplane namespaces" check_existence="none_exist" state_operator="AND">
      <ind:object object_ref="oval:ssg-object_configure_network_policies_filtered_namespaces:obj:1" />
    </ind:yamlfilecontent_test>
    <ind:variable_test id="oval:ssg-test_elements_count_for_configure_network_policies_namespaces:tst:1" version="1" check="all" comment="Count elements at both paths and compare" state_operator="AND">
      <ind:object object_ref="oval:ssg-object_elements_count_for_configure_network_policies_namespaces:obj:1" />
      <ind:state state_ref="oval:ssg-state_elements_count_for_configure_network_policies_namespaces:ste:1" />
    </ind:variable_test>
  </oval-def:tests>
  <oval-def:objects>
    <unix:file_object id="oval:ssg-object_file_for_configure_network_policies_namespaces:obj:1" version="1">
      <unix:filepath var_ref="oval:ssg-configure_network_policies_namespaces_file_location:var:1" />
    </unix:file_object>
    <unix:file_object id="oval:ssg-object_file_for_configure_network_policies_filtered_namespaces:obj:1" version="1">
      <unix:filepath var_ref="oval:ssg-configure_network_policies_filtered_namespaces_file_location:var:1" />
    </unix:file_object>
    <ind:yamlfilecontent_object id="oval:ssg-object_configure_network_policies_namespaces:obj:1" version="1">
      <ind:filepath var_ref="oval:ssg-configure_network_policies_namespaces_file_location:var:1" />
      <ind:yamlpath>[:]</ind:yamlpath>
    </ind:yamlfilecontent_object>
    <ind:yamlfilecontent_object id="oval:ssg-object_configure_network_policies_filtered_namespaces:obj:1" version="1">
      <ind:filepath var_ref="oval:ssg-configure_network_policies_filtered_namespaces_file_location:var:1" />
      <ind:yamlpath>[:].metadata.name</ind:yamlpath>
    </ind:yamlfilecontent_object>
    <ind:variable_object id="oval:ssg-object_elements_count_for_configure_network_policies_namespaces:obj:1" version="1">
      <ind:var_ref>oval:ssg-local_variable_counter_configure_network_policies_namespaces:var:1</ind:var_ref>
    </ind:variable_object>
  </oval-def:objects>
  <oval-def:states>
    <ind:variable_state id="oval:ssg-state_elements_count_for_configure_network_policies_namespaces:ste:1" version="1" operator="AND">
      <ind:value datatype="int" var_ref="oval:ssg-local_variable_counter_configure_network_policies_filtered_namespaces:var:1" />
    </ind:variable_state>
  </oval-def:states>
  <oval-def:variables>
    <oval-def:external_variable id="oval:ssg-ocp_data_root:var:1" version="1" datatype="string" comment="Root of OCP data dump" />
    <oval-def:local_variable id="oval:ssg-configure_network_policies_namespaces_file_location:var:1" version="1" datatype="string" comment="Path of file containing filtered non-ctlplane namespaces with network policies.">
      <oval-def:concat>
        <oval-def:variable_component var_ref="oval:ssg-ocp_data_root:var:1" />
        <oval-def:literal_component>/apis/networking.k8s.io/v1/networkpolicies#7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f</oval-def:literal_component>
      </oval-def:concat>
    </oval-def:local_variable>
    <oval-def:local_variable id="oval:ssg-configure_network_policies_filtered_namespaces_file_location:var:1" version="1" datatype="string" comment="Path of file containing filtered non-ctlplane namespaces.">
      <oval-def:concat>
        <oval-def:variable_component var_ref="oval:ssg-ocp_data_root:var:1" />
        <oval-def:literal_component>/api/v1/namespaces#f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2</oval-def:literal_component>
      </oval-def:concat>
    </oval-def:local_variable>
    <oval-def:local_variable id="oval:ssg-local_variable_counter_configure_network_policies_namespaces:var:1" version="1" datatype="int" comment="Items counter">
      <oval-def:count>
        <oval-def:object_component object_ref="oval:ssg-object_configure_network_policies_namespaces:obj:1" item_field="value" record_field="#" />
      </oval-def:count>
    </oval-def:local_variable>
    <oval-def:local_variable id="oval:ssg-local_variable_counter_configure_network_policies_filtered_namespaces:var:1" version="1" datatype="int" comment="Items counter control">
      <oval-def:count>
        <oval-def:object_component object_ref="oval:ssg-object_configure_network_policies_filtered_namespaces:obj:1" item_field="value" record_field="#" />
      </oval-def:count>
    </oval-def:local_variable>
  </oval-def:variables>
</oval-def:oval_definitions>
```

Which requires the following overloading to fetch `Namespace` and `NetworkPolicy` resources:

```xml
<html:ul>
	<html:li>
		<html:code class="ocp-api-endpoint" id="7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f">/apis/networking.k8s.io/v1/networkpolicies</html:code>
    API endpoint, filter with with the
		<html:code>jq</html:code> utility using the following filter
		<html:code class="ocp-api-filter" id="filter-7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f">[.items[] | select((.metadata.namespace | startswith("openshift") | not) and (.metadata.namespace | startswith("kube-") | not) and .metadata.namespace != "default" and ({{if ne .var_network_policies_namespaces_exempt_regex "None"}}.metadata.namespace | test("{{.var_network_policies_namespaces_exempt_
regex}}") | not{{else}}true{{end}})) | .metadata.namespace] | unique</html:code>
    and persist it to the local
		<html:code class="ocp-dump-location" id="dump-7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f">
			<xccdf-1.2:sub idref="xccdf_org.ssgproject.content_value_ocp_data_root" use="legacy" />/apis/networking.k8s.io/v1/networkpolicies#7400bb301fff2f7fc7b1b0fb7448b8e3f15222a8d23f992204315b19eeefa72f
		</html:code>
    file.
	</html:li>
	<html:li>
		<html:code class="ocp-api-endpoint" id="f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2">/api/v1/namespaces</html:code>
    API endpoint, filter with with the
		<html:code>jq</html:code> utility using the following filter
		<html:code class="ocp-api-filter" id="filter-f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2">[.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default" and ({{if ne .var_network_policies_namespaces_exempt_regex "None"}}.metadata.name | test("{{.var_network_policies_namespaces_exempt_regex}}") | not{{els
e}}true{{end}}))]</html:code>
    and persist it to the local
		<html:code class="ocp-dump-location" id="dump-f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2">
			<xccdf-1.2:sub idref="xccdf_org.ssgproject.content_value_ocp_data_root" use="legacy" />/api/v1/namespaces#f673748db2dd4e4f0ad55d10ce5e86714c06da02b67ddb392582f71ef81efab2
		</html:code>
    file.
	</html:li>
</html:ul>
```

To summarize, the compliance content, which is made up of profiles that contain
rules, is written in YAML for basic usecases. More complex usecases where we
need to evaluate aspects of the OpenShift platform, like configuration or
resources, require handcrafted XML that overloads aspects of the SCAP and OVAL
standards to pass data around.

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



