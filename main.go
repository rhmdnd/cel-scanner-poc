package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

var ruleFile string

type rule struct {
	Kind         string  `yaml:"kind"`
	CheckType    string  `yaml:"checkType"`
	Title        string  `yaml:"title"`
	Expression   string  `yaml:"expression"`
	Inputs       []input `yaml:"inputs"`
	ErrorMessage string  `yaml:"errorMessage"`
}

type input struct {
	// Name of the input, it could be referenced in the expression
	Name string `yaml:"name"`
	// Type of the input, it could be a kube GroupVersionResource or a file or a kube api path
	Type        string `yaml:"type"`
	ApiGroup    string `yaml:"apiGroup"`
	Version     string `yaml:"version"`
	Resource    string `yaml:"resource"`
	SubResource string `yaml:"subResource,omitempty"`
	Namespace   string `yaml:"namespace,omitempty"`
	Path        string `yaml:"path"`
}

func main() {
	validate()

	r := read(ruleFile)

	// collect dependencies (e.g., get file metadata information or Kubernetes resource information)
	resultMap := collect(r)

	declsList := []*expr.Decl{}

	for k, _ := range resultMap {
		// build a CEL environment with the rule expression
		declsList = append(declsList, decls.NewVar(k, decls.Dyn))
	}

	mapStrDyn := cel.MapType(cel.StringType, cel.DynType)
	var jsonenvOpts cel.EnvOption = cel.Function("parseJSON",
		cel.MemberOverload("parseJSON_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseJSONString)))
	var yamlenvOpts cel.EnvOption = cel.Function("parseYAML",
		cel.MemberOverload("parseYAML_string",
			[]*cel.Type{cel.StringType}, mapStrDyn, cel.UnaryBinding(parseYAMLString)))

	// build a CEL environment with the rule expression
	env, err := cel.NewEnv(
		cel.Declarations(declsList...), jsonenvOpts, yamlenvOpts,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to create CEL environment: %s", err))
	}

	// compile the CEL expression
	ast, issues := env.Compile(r.Expression)
	if issues.Err() != nil {
		panic(fmt.Sprintf("Failed to compile CEL expression: %s", issues.Err()))
	}

	evalVars := map[string]interface{}{}
	for k, v := range resultMap {
		evalVars[k] = toCelValue(v)
	}

	// evaluate the CEL program with the inputs
	prg, err := env.Program(ast)
	if err != nil {
		panic(fmt.Sprintf("Failed to create CEL program: %s", err))
	}

	out, _, err := prg.Eval(evalVars)
	if err != nil {
		if strings.HasPrefix(err.Error(), "no such key:") {
			fmt.Printf("Warning: %s in %s/%s\n", err, r.Inputs[0].Resource, r.Inputs[0].SubResource)
			fmt.Printf("Evaluation result: false\n")
			return
		}
		panic(fmt.Sprintf("Failed to evaluate CEL expression: %s", err))
	}

	// report the findings
	if out.Value() == false {
		fmt.Println(r.ErrorMessage)
	}
	fmt.Printf("%s: %v\n", r.Title, out)
}

func parseJSONString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := json.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseJSON: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseJSON: %w", err)
	}

	return types.NewDynamicMap(r, decodedVal)
}

func parseYAMLString(val ref.Val) ref.Val {
	str := val.(types.String)
	decodedVal := map[string]interface{}{}
	err := yaml.Unmarshal([]byte(str), &decodedVal)
	if err != nil {
		return types.NewErr("failed to decode '%v' in parseYAML: %w", str, err)
	}
	r, err := types.NewRegistry()
	if err != nil {
		return types.NewErr("failed to create a new registry in parseJSON: %w", err)
	}
	return types.NewDynamicMap(r, decodedVal)
}

func toCelValue(u interface{}) interface{} {
	if unstruct, ok := u.(*unstructured.Unstructured); ok {
		return unstruct.Object
	}
	if unstructList, ok := u.(*unstructured.UnstructuredList); ok {
		list := []interface{}{}
		for _, item := range unstructList.Items {
			list = append(list, item.Object)
		}
		return map[string]interface{}{
			"items": list,
		}
	}
	return nil
}

// Validate inputs
func validate() {
	flag.StringVar(&ruleFile, "i", "", "Path to a YAML file containing a rule")
	flag.Parse()

	if ruleFile == "" {
		panic("Must use -i to pass in a rule file")
	}
}

// Read a file as a given path `p` and return a rule struct that represents the
// YAML contents.
func read(p string) *rule {
	r := rule{}

	f, err := os.ReadFile(p)
	if err != nil {
		panic(fmt.Sprintf("Failed to read %s: %s", p, err))
	}
	err = yaml.Unmarshal(f, &r)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse YAML: %s", err))
	}
	return &r
}

// Collect all the dependencies for a given rule
func collect(r *rule) map[string]interface{} {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		panic("You must export KUBECONFIG for this tool to fetch Kubernetes resources")
	}
	// add logging here

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// Create a new dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	// create context
	ctx := context.TODO()

	resultMap := make(map[string]interface{})

	// fetch the resources and store them in a map
	if r.CheckType == "Platform" {
		if r.Inputs != nil {
			for _, input := range r.Inputs {
				if input.Type == "KubeGroupVersionResource" {
					// fetch the resource
					// add logging here
					gvr := schema.GroupVersionResource{
						Group:    input.ApiGroup,
						Version:  input.Version,
						Resource: input.Resource,
					}
					results := &unstructured.UnstructuredList{}
					result := &unstructured.Unstructured{}
					if input.SubResource != "" {
						if input.Namespace == "" {
							result, err = dynamicClient.Resource(gvr).Get(ctx, input.SubResource, metav1.GetOptions{})
							if err != nil {
								panic(err)
							}
						} else {
							result, err = dynamicClient.Resource(gvr).Namespace(input.Namespace).Get(ctx, input.SubResource, metav1.GetOptions{})
							if err != nil {
								panic(err)
							}
						}
						resultMap[input.Name] = result
					} else {
						if input.Namespace == "" {
							results, err = dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
							if err != nil {
								panic(err)
							}
						} else {
							results, err = dynamicClient.Resource(gvr).Namespace(input.Namespace).List(ctx, metav1.ListOptions{})
							if err != nil {
								panic(err)
							}
						}
						resultMap[input.Name] = results
					}

					if results == nil && result == nil {
						panic("Failed to fetch the resource")
					}

				}
			}
		}
	}

	return resultMap
}
