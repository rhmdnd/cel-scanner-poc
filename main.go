package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

var ruleFile string

type rule struct {
	Kind       string   `yaml:"kind"`
	CheckType  string   `yaml:"checkType"`
	Title      string   `yaml:"title"`
	Expression string   `yaml:"expression"`
	Inputs     []string `yaml:"inputs"`
}

func main() {
	validate()

	read(ruleFile)

	// collect dependencies (e.g., get file metadata information or
	// Kubernetes resource information)

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
