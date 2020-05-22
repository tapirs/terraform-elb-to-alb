package elbtoalbtools

import (
  "fmt"
  "log"
  "os"
  "bufio"
  "strings"
  "path/filepath"
  "io/ioutil"
  "strconv"
  "regexp"
)

var postMappings map[string]string
var myMappings map[string]string

func Post() error {
  log.Println("post")

  postMappings = make(map[string]string, 0)
  myMappings = make(map[string]string, 0)

  readMappings()
  readMyMappings()
  readTFFiles()

  return nil
}

func readMyMappings() error {
  file, err := os.Open("elbtoalb-output/myMappings.txt")
  if err != nil {
    log.Println(err)
    return err
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    line := scanner.Text()
    if equal := strings.Index(line, "="); equal >= 0 {
      if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
          value := ""
          if len(line) > equal {
            value = strings.TrimSpace(line[equal+1:])
          }
        myMappings[key] = value
      }
    }
  }

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
    return err
  }

  return nil
}

func readMappings() error {
  file, err := os.Open("elbtoalb-output/mappings.txt")
  if err != nil {
    log.Println(err)
    return err
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    line := scanner.Text()
    if equal := strings.Index(line, "=tags"); equal >= 0 {
      if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
          value := ""
          if len(line) > equal {
            value = strings.TrimSpace(line[equal+5:])
          }
        postMappings[key] = value
      }
    } else if equal := strings.Index(line, "="); equal >= 0 {
      if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
          value := ""
          if len(line) > equal {
            value = strings.TrimSpace(line[equal+1:])
          }
        postMappings[key] = value
      }
    }
  }

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
    return err
  }

  return nil
}

func readTFFiles() error {
  err := filepath.Walk("./lb_terraform",
    func(path string, info os.FileInfo, err error) error {
    if err != nil {
        return err
    }
    if filepath.Ext(path) == ".tf" {
      dat, err := ioutil.ReadFile(path)
      if err != nil {
        log.Println(err)
        return err
      }

      replaced := replaceMyMappings(string(dat))

      replaced = replacePostMappings(replaced)

      err = writeTFFiles(path, replaced)
      if err != nil {
        log.Println(err)
        return err
      }

      log.Println("path is - " + path)

      if path != "lb_terraform/lb.tf" {
        err = appendTFFile("./lb_terraform/lb.tf", replaced)
        if err != nil {
          log.Println(err)
          return err
        }
      }

    }
    return nil
  })
  if err != nil {
    log.Println(err)
    return err
  }

  return nil
}

func writeTFFiles(filename string, data string) error {
  f, err := os.Create(fmt.Sprintf("%s", filename))
  if err != nil {
    log.Println(err)
    return err
  }

  defer f.Close()

  w := bufio.NewWriter(f)
  _, err = w.WriteString(data)
  if err != nil {
    log.Println(err)
    return err
  }

  w.Flush()

  return nil
}

func appendTFFile(filename string, data string) error {
  f, err := os.OpenFile(fmt.Sprintf("%s", filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
  if err != nil {
    log.Println(err)
    return err
  }

  defer f.Close()

  w := bufio.NewWriter(f)
  _, err = w.WriteString("\n\n" + data)
  if err != nil {
    log.Println(err)
    return err
  }

  w.Flush()

  return nil
}

func replaceMyMappings(data string) string {
  replaced := data
  for key, value := range myMappings {
    replaced = strings.ReplaceAll(replaced, key, value)
  }

  return replaced
}

func replacePostMappings(data string) string {
  replaced := data
  for key, value := range postMappings {
    if _, err := strconv.Atoi(value); err == nil {
      r, _ := regexp.Compile(`(?s) ` + value + `\n`)

      replaced = r.ReplaceAllString(replaced, " " + key + "\n")
    } else if strings.Contains(key, "resource") {
      r, _ := regexp.Compile(`(?m)resource \"aws_lb\" \"(.*` + value + `.*)\"`)

      resourceName := strings.Replace(key, "resource_", "", -1)
      resourceName = strings.Replace(resourceName, "elb", "lb", -1)

      replaced = r.ReplaceAllString(replaced, "resource \"aws_lb\" \"" + resourceName + "\"")
    } else {
      replaced = strings.ReplaceAll(replaced, value, key)
    }
    // replaced = strings.ReplaceAll(replaced, "${" + key + "}", value)
    // replaced = strings.ReplaceAll(replaced, "[" + key + "]", value)

  }

  replaced = removeVariablesFromResourceName(replaced)

  return replaced
}

func removeVariablesFromResourceName(replaced string) string {
  r, _ := regexp.Compile(`(?m)resource \"(aws_.*)\" \"(.*)-\$\{.*\}(.*)\"`)

  replaced = r.ReplaceAllString(replaced, "resource \"$1\" \"$2$3\" ")

  return replaced
}
