package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"k8s.io/client-go/kubernetes"
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
	Type     string `yaml:"type"`
	ApiGroup string `yaml:"apiGroup"`
	Version  string `yaml:"version"`
	Resource string `yaml:"resource"`
}

func main() {
	validate()

	r := read(ruleFile)

	// collect dependencies (e.g., get file metadata information or
	// Kubernetes resource information)
	collect(r)

	// build a CEL scanning instance with the rule expression

	// run the CEL program with the inputs

	// report the findings
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

	f, err := ioutil.ReadFile(p)
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
func collect(r *rule) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		panic("You must export KUBECONFIG for this tool to fetch Kubernetes resources")
	}
	fmt.Printf("Using %s to establish connection with cluster\n", kubeconfig)

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	_, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// TBD on the return definition, since it can being anything with the kubernetes ecosystem...
}
