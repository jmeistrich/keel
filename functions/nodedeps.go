package functions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/aybabtme/orderedjson"
	"github.com/samber/lo"
)

var DEV_DEPENDENCIES = map[string]string{
	"@types/node":       "^18.0.6",
	"typescript":        "^4.7.4",
	"@teamkeel/runtime": "*",
	"@teamkeel/sdk":     "*",
}

// We don't require any dependencies at the minute
var DEPENDENCIES = map[string]string{}

type Dependencies = map[string]string

type PackageJson struct {
	// Meta fields
	Path     string `json:"-"`
	Contents string `json:"-"`

	// Dev + normal dependencies defined in the json file
	Dependencies    Dependencies `json:"dependencies"`
	DevDependencies Dependencies `json:"devDependencies"`
}

// Instantiates an in memory representation of a package.json file.
// The relevant entries (devDependencies / dependencies) we are
// interested in are unmarshalled into memory
func NewPackageJson(path string) (*PackageJson, error) {
	p := PackageJson{
		Path: path,
	}

	// If the package.json doesnt exist in the working directory
	// then we need to generate the default with npm init -y
	// However, the package.json generated by npm init lacks devDependencies / dependencies
	// so we need to write empty sections for these keys
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		cmd := exec.Command("npm", "init", "-y")
		cmd.Dir = filepath.Dir(path)

		err := cmd.Run()

		if err != nil {
			return nil, err
		}

		err = p.ReadIntoMemory()

		if err != nil {
			return nil, err
		}

		p.Dependencies = map[string]string{}
		p.DevDependencies = map[string]string{}

		err = p.Write()

		if err != nil {
			return nil, err
		}
	} else {
		err = p.ReadIntoMemory()

		if err != nil {
			return nil, err
		}
	}

	return &p, nil
}

func (r *PackageJson) Bootstrap() error {
	err := r.Inject(DEV_DEPENDENCIES, true)

	if err != nil {
		return err
	}

	return nil
}

// Runs npm install on the current *written* state of the package.json file, causing node_modules to be populated, and the lockfile to be updated
// Call .Write() beforehand to persist any changes made.
func (p *PackageJson) Install() error {
	npmInstall := exec.Command("npm", "install")
	npmInstall.Dir = filepath.Dir(p.Path)

	o, err := npmInstall.CombinedOutput()

	if err != nil {
		fmt.Print(string(o))
		return err
	}

	return nil
}

// ReadIntoMemory reads from the package.json file at path
// and unmarshals the contents into memory
// This will overwrite any changes made in memory
func (p *PackageJson) ReadIntoMemory() error {
	bytes, err := os.ReadFile(p.Path)

	if err != nil {
		return err
	}

	p.Contents = string(bytes)

	err = json.Unmarshal(bytes, &p)

	if err != nil {
		return err
	}

	return nil
}

// Inject devDependencies into the package.json file
// Where there are matching packages already, the version we inject overwrites the original
func (p *PackageJson) Inject(deps map[string]string, dev bool) error {
	if dev {
		if p.DevDependencies != nil {
			d := p.DevDependencies

			for packageName, version := range deps {
				if _, found := d[packageName]; found {
					d[packageName] = version
				} else {
					d[packageName] = version
				}
			}
		} else {
			var d = map[string]string{}

			for packageName, version := range deps {
				d[packageName] = version
			}

			p.DevDependencies = d
		}
	}

	if !dev {
		if p.Dependencies != nil {
			d := p.Dependencies

			for packageName, version := range deps {
				if originalVersion, found := d[packageName]; found {
					d[packageName] = originalVersion
				} else {
					d[packageName] = version
				}
			}
		} else {
			var d = map[string]string{}

			for packageName, version := range deps {
				d[packageName] = version
			}

			p.Dependencies = d
		}
	}

	err := p.Write()

	if err != nil {
		return err
	}

	return nil
}

var (
	KeyDependencies    = "dependencies"
	KeyDevDependencies = "devDependencies"
)

// Write will inject any changes made in memory to the target
// package.json
// Using standard Marshal/Unmarshal into a map[string]interface{}
// does not guarantee that the keys will be serialized in the order originally specified
// so we need to use a special orderjson.Map objec to ensure the order is not disturbed
func (p *PackageJson) Write() error {
	var originalPackageJson orderedjson.Map
	var mutatedPackageJson orderedjson.Map

	err := json.Unmarshal([]byte(p.Contents), &originalPackageJson)

	if err != nil {
		return err
	}

	// check for existence of devDependencies / dependencies sections
	hasDevDeps := lo.ContainsBy(originalPackageJson, func(entry orderedjson.MapEntry) bool {
		k, err := strconv.Unquote(string(entry.Key))

		if err != nil {
			return false
		}

		if k == KeyDevDependencies {
			return true
		}

		return false
	})

	hasDeps := lo.ContainsBy(originalPackageJson, func(entry orderedjson.MapEntry) bool {
		k, err := strconv.Unquote(string(entry.Key))

		if err != nil {
			return false
		}

		if k == KeyDependencies {
			return true
		}

		return false
	})

	if !hasDevDeps {
		mutatedPackageJson = append(mutatedPackageJson, orderedjson.MapEntry{
			Key:   json.RawMessage(strconv.Quote(KeyDevDependencies)),
			Value: json.RawMessage([]byte("{}")),
		})
	}

	if !hasDeps {
		mutatedPackageJson = append(mutatedPackageJson, orderedjson.MapEntry{
			Key:   json.RawMessage(strconv.Quote(KeyDependencies)),
			Value: json.RawMessage([]byte("{}")),
		})
	}

	for _, entry := range originalPackageJson {
		k, err := strconv.Unquote(string(entry.Key))

		if err != nil {
			continue
		}

		switch k {
		case KeyDevDependencies:
			b, err := json.Marshal(p.DevDependencies)

			if err != nil {
				return err
			}

			entry.Value = json.RawMessage(b)
		case KeyDependencies:
			b, err := json.Marshal(p.Dependencies)

			if err != nil {
				return err
			}

			entry.Value = json.RawMessage(b)
		}

		mutatedPackageJson = append(mutatedPackageJson, entry)
	}

	marshalled, err := mutatedPackageJson.MarshalJSON()
	if err != nil {
		return err
	}
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, marshalled, "", "  ")

	if err != nil {
		return err
	}
	err = os.WriteFile(p.Path, prettyJSON.Bytes(), 0644)

	if err != nil {
		return err
	}

	// Update the lockfile
	err = p.Install()

	if err != nil {
		return err
	}

	p.Contents = prettyJSON.String()

	return nil
}
