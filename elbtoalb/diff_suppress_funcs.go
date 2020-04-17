package elbtoalb

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/jen20/awspolicyequivalence"
)

func suppressEquivalentAwsPolicyDiffs(k, old, new string, d *schema.ResourceData) bool {
	equivalent, err := awspolicy.PoliciesAreEquivalent(old, new)
	if err != nil {
		return false
	}

	return equivalent
}

// suppressEquivalentTypeStringBoolean provides custom difference suppression for TypeString booleans
// Some arguments require three values: true, false, and "" (unspecified), but
// confusing behavior exists when converting bare true/false values with state.
func suppressEquivalentTypeStringBoolean(k, old, new string, d *schema.ResourceData) bool {
	if old == "false" && new == "0" {
		return true
	}
	if old == "true" && new == "1" {
		return true
	}
	return false
}

// suppressMissingOptionalConfigurationBlock handles configuration block attributes in the following scenario:
//  * The resource schema includes an optional configuration block with defaults
//  * The API response includes those defaults to refresh into the Terraform state
//  * The operator's configuration omits the optional configuration block
func suppressMissingOptionalConfigurationBlock(k, old, new string, d *schema.ResourceData) bool {
	return old == "1" && new == "0"
}

func suppressEquivalentJsonDiffs(k, old, new string, d *schema.ResourceData) bool {
	ob := bytes.NewBufferString("")
	if err := json.Compact(ob, []byte(old)); err != nil {
		return false
	}

	nb := bytes.NewBufferString("")
	if err := json.Compact(nb, []byte(new)); err != nil {
		return false
	}

	return jsonBytesEqual(ob.Bytes(), nb.Bytes())
}

func suppressRoute53ZoneNameWithTrailingDot(k, old, new string, d *schema.ResourceData) bool {
	// "." is different from "".
	if old == "." || new == "." {
		return old == new
	}
	return strings.TrimSuffix(old, ".") == strings.TrimSuffix(new, ".")
}
