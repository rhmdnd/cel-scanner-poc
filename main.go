package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
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
	Kind       string  `yaml:"kind"`
	CheckType  string  `yaml:"checkType"`
	Title      string  `yaml:"title"`
	Expression string  `yaml:"expression"`
	Inputs     []input `yaml:"inputs"`
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

	for k, v := range resultMap {
		fmt.Printf("Key: %s\nValue: %v\n", k, v)
		// build a CEL environment with the rule expression
		declsList = append(declsList, decls.NewVar(k, decls.Dyn))
	}

	// build a CEL environment with the rule expression
	env, err := cel.NewEnv(
		cel.Declarations(declsList...),
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
	fmt.Printf("Evaluation result: %v\n", out)
}

// toCelValue converts an unstructured.Unstructured object to a format compatible with CEL
func toCelValue(u interface{}) map[string]interface{} {
	if unstruct, ok := u.(*unstructured.Unstructured); ok {
		return unstruct.Object
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
	fmt.Printf("Using %s to establish connection with cluster\n", kubeconfig)

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
					fmt.Printf("Fetching %s/%s/%s/%s\n", input.ApiGroup, input.Version, input.Resource, input.SubResource)
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
