package elbtoalbtools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var mappings map[string]string
var matches []string

type Issues struct {
	Valid         bool
	Error_count   int
	Warning_count int
	Diagnostics   []Issue
}

type Issue struct {
	Severity string
	Summary  string
	Detail   string
	Range    struct {
		Filename string
		Start    struct {
			Line   int
			Column int
			Byte   int
		}
		End struct {
			Line   int
			Column int
			Byte   int
		}
	}
}

func Pre(tf_dir string) error {
	log.Println("Starting pre-processing of terraform")

	mappings = make(map[string]string)
	mappings["aws_elb"] = "elbtoalb_elb"

	err := os.MkdirAll("./elbtoalb-output", 0755)
	if err != nil {
		log.Println(err)
		return err
	}

  log.Println("Gatherings all terraform files with elb resources under " + tf_dir)
	err = filepath.Walk(tf_dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
        log.Println(err)
				return err
			}
			if filepath.Ext(path) == ".tf" {
        log.Println("Found a terraform file - " + path)
				r, err := regexp.Compile(`(?s)resource \"aws_elb\".*?\n}\n`)
				if err != nil {
					log.Println(err)
					return err
				}
				dat, err := ioutil.ReadFile(path)
				if err != nil {
					log.Println(err)
					return err
				}

        log.Println("Processing " + path)
				err = processMatches(r.FindAllString(string(dat), -1))
				if err != nil {
					log.Println(err)
					return err
				}

				new_dat := r.ReplaceAllString(string(dat), "")

				r, err = regexp.Compile(`(?s)aws_elb\..*?\.`)
				if err != nil {
					log.Println(err)
					return err
				}

				new_dat = r.ReplaceAllString(new_dat, "aws_lb.lb.")

				// elb_matches := r.FindStringSubmatch(new_dat)
				//
				// fmt.Println(elb_matches)
				//
				// for _, elb_match := range elb_matches {
				//   new_dat = strings.ReplaceAll(new_dat, "aws_elb." + elb_match, "aws_lb.lb")
				// }

				f, err := os.Create(path)
				if err != nil {
					return err
				}

				w := bufio.NewWriter(f)

				_, err = w.WriteString(string(new_dat))
				if err != nil {
					return err
				}

				w.Flush()
			}
			return nil
		})
	if err != nil {
		log.Println(err)
		return err
	}

	err = createOutput(matches)
	if err != nil {
		log.Println(err)
		return err
	}

	err = validateTerraform()
	if err != nil {
		return err
	}

	err = createMappingsOutput()
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func getResourceName(match string) error {
	r, err := regexp.Compile(`(?m)resource \"aws_elb\" \"(.*)\"`)
	if err != nil {
		return err
	}

	subMatches := r.FindSubmatch([]byte(match))
	currentResourceName := string(subMatches[1])

	r, err = regexp.Compile(`(?s)(.*?)(-|_)?elb(-|_)?(.*)`)
  if err != nil {
    return err
  }
	subMatches = r.FindSubmatch([]byte(currentResourceName))

	mappings["resource_"+currentResourceName] = string(subMatches[1]) + string(subMatches[4])

	// fmt.Println(currentResourceName)

	return nil
}

func processMatches(regexMatches []string) error {
	for _, match := range regexMatches {


		err := getResourceName(match)
		if err != nil {
			return err
		}


		match = replaceMappings(match)

		match, err := mapLocal(match)
		if err != nil {
			return err
		}
		match, err = mapData(match)
		if err != nil {
			return err
		}
		match, err = mapAWS(match)
		if err != nil {
			return err
		}
		match, err = mapVars(match)
		if err != nil {
			return err
		}
		// match, err = mapTags(match)
		// if err != nil {
		// 	return err
		// }

		// fmt.Println(match)

		matches = append(matches, match)
		// fmt.Println(matches)
	}

	return nil
}

func replaceMappings(match string) string {
  log.Println("Replacing any known mappings")
  log.Println(mappings)
  // log.Println(match)
	replaced := match
	for key, value := range mappings {
		replaced = strings.ReplaceAll(replaced, key, value)
	}

	return replaced
}

func validateTerraform() error {
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader("cd elbtoalb-output; terraform init -no-color")

	if err := cmd.Run(); err != nil {
		log.Println(err)
		return err
	}

	cmd = exec.Command("bash")
	cmd.Stdin = strings.NewReader("cd elbtoalb-output; terraform validate -json -no-color")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println(err)
		return err
	}

	if err := cmd.Start(); err != nil {
		log.Println(err)
		return err
	}

	var issues Issues

	if err := json.NewDecoder(stdout).Decode(&issues); err != nil {
		log.Println(err)
		return err
	}

	// fmt.Println(issues)

	for _, issue := range issues.Diagnostics {
		err = diagnoseIssue(issue)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func diagnoseIssue(issue Issue) error {
  log.Println("Diagnosing the issue - " + issue.Detail)
	var newMatches []string

	switch {
	case strings.Contains(issue.Detail, "a number is required"):
		r, _ := regexp.Compile(`(?s).*\"(.*)\".*`)

		subMatches := r.FindSubmatch([]byte(issue.Detail))
		issueProperty := string(subMatches[1])

		re, _ := regexp.Compile(`` + issueProperty + `.*= (.*)`)

		for _, match := range matches {
			subMatch := re.FindSubmatch([]byte(match))
			if _, err := strconv.Atoi(string(subMatch[1])); err != nil {
				matchString := strings.ReplaceAll(string(subMatch[1]), "\"", "")
				// fmt.Println(matchString)
				if issueProperty == "interval" {
					mappings[matchString] = "5"
					// fmt.Println(mappings)
				} else {
					s1 := rand.NewSource(time.Now().UnixNano())
					r1 := rand.New(s1)
					mappings[string(subMatch[1])] = string(r1.Intn(100))
				}
				match = replaceMappings(match)
			}
			newMatches = append(newMatches, match)
			// fmt.Println(match)

      err := createOutput(newMatches)
    	if err != nil {
    		log.Println(err)
    		return err
    	}
		}
  case strings.Contains(issue.Detail, "set of string required."):
    r, _ := regexp.Compile(`(?s).*\"(.*)\".*`)

		subMatches := r.FindSubmatch([]byte(issue.Detail))
		issueProperty := string(subMatches[1])

    re, _ := regexp.Compile(`` + issueProperty + `.*= (.*)`)

    for _, match := range matches {
			subMatch := re.FindSubmatch([]byte(match))
      if len(subMatch) > 0 {
        log.Println(string(subMatch[1]))
        matchString := string(subMatch[1])
        log.Println(matchString)
        if !(strings.HasPrefix(matchString, "[") && strings.HasSuffix(matchString, "]")) {
          mappings[matchString] = "[" + matchString + "]"


        }
        match = replaceMappings(match)
      }
      newMatches = append(newMatches, match)

      err := createOutput(newMatches)
    	if err != nil {
    		log.Println(err)
    		return err
    	}
		}
	default:
		fmt.Println("unable to find the issue")
	}

	return nil
}

func mapLocal(match string) (string, error) {
  log.Println("Mapping local variables")
	r, _ := regexp.Compile(`(?s)\$?[{\[]local\.\w*[}\]]`)

	locals := r.FindAllString(match, -1)

	for _, local := range locals {
		if _, ok := mappings[local]; !ok {
			mappings[local] = variableName(local)
		}
	}

	match = replaceMappings(match)

	return match, nil
}

func mapData(match string) (string, error) {
  log.Println("Mapping data variables")
	r, err := regexp.Compile(`(?m)\$?({|\[)?data\..*(}|])?`)
	if err != nil {
		log.Println(err)
		return "", err
	}

	data := r.FindAllString(match, -1)

	fmt.Println(data)

	for _, datum := range data {
		datum = strings.Replace(datum, ",", "", 1)
		if _, ok := mappings[datum]; !ok {
			mappings[datum] = "\"" + variableName(datum) + "\""
		}
	}

	match = replaceMappings(match)

	return match, nil
}

func mapAWS(match string) (string, error) {
	r, _ := regexp.Compile(`(?m)\$?({|\[)?aws_.*(}|])?`)

	awsResources := r.FindAllString(match, -1)

	// fmt.Println(awsResources)

	for _, awsResource := range awsResources {
		awsResource = strings.Replace(awsResource, ",", "", 1)
		if _, ok := mappings[awsResource]; !ok {
			mappings[awsResource] = "\"" + variableName("aws."+awsResource) + "\""
		}
	}

	match = replaceMappings(match)

	return match, nil
}

func mapVars(match string) (string, error) {
	r, _ := regexp.Compile(`(?m)\$?({|\[)?var\..*(}|])?`)

	vars := r.FindAllString(match, -1)

	// fmt.Println(data)

	for _, variable := range vars {
		variable = strings.Replace(variable, ",", "", 1)
		if _, ok := mappings[variable]; !ok {
			mappings[variable] = "\"" + variableName(variable) + "\""
		}
	}

	match = replaceMappings(match)

	return match, nil
}

func mapTags(match string) (string, error) {
	r, _ := regexp.Compile(`(?s)tags =.*?[)}]\n`)

	tags := r.FindString(match)

	// fmt.Println(tags)
	mappings[tags] = "tags = { \"tags\" = \"" + strings.ReplaceAll(strings.ReplaceAll(tags, "\"", "\\\\\\\""), "\n", "") + "\"}\n"

	match = replaceMappings(match)

	return match, nil
}

func createOutput(output []string) error {
  log.Println("Creating output terraform file")
	f, err := os.Create("./elbtoalb-output/elbtoalb.tf")
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)

	for _, entry := range output {
		_, err = w.WriteString(entry)
		if err != nil {
			return err
		}
	}

	w.Flush()

	return nil
}

func createMappingsOutput() error {
  log.Println("Creating mappings file")
	f, err := os.Create("./elbtoalb-output/mappings.txt")
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)

	for key, val := range mappings {
		_, err = w.WriteString(strings.ReplaceAll(key, "\n", "") + "=" + val + "\n")
    if err != nil {
			return err
		}
	}

	w.Flush()

	return nil
}

func variableName(variable string) string {
	varName := "e2a"

	afterDot := strings.Split(variable, ".")

	for i, section := range afterDot {
		if i != 0 {
			switch section {
			case "terraform_remote_state":
				section = "trs"
			case "outputs":
				section = ""
			}
			section = strings.ReplaceAll(section, "_", "-")
			sectionSections := strings.Split(section, "-")
			for _, sectionSection := range sectionSections {
				if len(sectionSection) >= 3 {
					varName = varName + "-" + sectionSection[0:3]
				} else if len(sectionSection) > 0 {
					varName = varName + "-" + sectionSection
				}
			}
		}
	}

	if strings.HasPrefix(variable, "${") {
		varName = varName + "-br"
	} else if strings.HasPrefix(variable, "[") {
		varName = varName + "-sq"
	}

	return varName
}
