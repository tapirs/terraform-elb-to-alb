package elbtoalb

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

const (
	awsAccountIDRegexpPattern = `^(aws|\d{12})$`
	awsPartitionRegexpPattern = `^aws(-[a-z]+)*$`
	awsRegionRegexpPattern    = `^[a-z]{2}(-[a-z]+)+-\d$`
)

var awsAccountIDRegexp = regexp.MustCompile(awsAccountIDRegexpPattern)
var awsPartitionRegexp = regexp.MustCompile(awsPartitionRegexpPattern)
var awsRegionRegexp = regexp.MustCompile(awsRegionRegexpPattern)

// validateTypeStringNullableBoolean provides custom error messaging for TypeString booleans
// Some arguments require three values: true, false, and "" (unspecified).
// This ValidateFunc returns a custom message since the message with
// validation.StringInSlice([]string{"", "false", "true"}, false) is confusing:
// to be one of [ false true], got 1
func validateTypeStringNullableBoolean(v interface{}, k string) (ws []string, es []error) {
	value, ok := v.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	for _, str := range []string{"", "0", "1", "false", "true"} {
		if value == str {
			return
		}
	}

	es = append(es, fmt.Errorf("expected %s to be one of [\"\", false, true], got %s", k, value))
	return
}

// validateTypeStringNullableFloat provides custom error messaging for TypeString floats
// Some arguments require a floating point value or an unspecified, empty field.
func validateTypeStringNullableFloat(v interface{}, k string) (ws []string, es []error) {
	value, ok := v.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if value == "" {
		return
	}

	if _, err := strconv.ParseFloat(value, 64); err != nil {
		es = append(es, fmt.Errorf("%s: cannot parse '%s' as float: %s", k, value, err))
	}

	return
}

func validateTransferServerID(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	// https://docs.aws.amazon.com/transfer/latest/userguide/API_CreateUser.html
	pattern := `^s-([0-9a-f]{17})$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q isn't a valid transfer server id (only lowercase alphanumeric characters are allowed): %q",
			k, value))
	}

	return
}

func validateTransferUserName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	// https://docs.aws.amazon.com/transfer/latest/userguide/API_CreateUser.html
	if !regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]{2,31}$`).MatchString(value) {
		errors = append(errors, fmt.Errorf("Invalid %q: must be between 3 and 32 alphanumeric or special characters hyphen and underscore. However, %q cannot begin with a hyphen", k, k))
	}
	return
}

// validateTagFilters confirms the "value" component of a tag filter is one of
// AWS's three allowed types.
func validateTagFilters(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if value != "KEY_ONLY" && value != "VALUE_ONLY" && value != "KEY_AND_VALUE" {
		errors = append(errors, fmt.Errorf(
			"%q must be one of \"KEY_ONLY\", \"VALUE_ONLY\", or \"KEY_AND_VALUE\"", k))
	}
	return
}

func validateElbName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if len(value) == 0 {
		return // short-circuit
	}
	if len(value) > 32 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 32 characters: %q", k, value))
	}
	if !regexp.MustCompile(`^[0-9A-Za-z-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"only alphanumeric characters and hyphens allowed in %q: %q",
			k, value))
	}
	if regexp.MustCompile(`^-`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot begin with a hyphen: %q", k, value))
	}
	if regexp.MustCompile(`-$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot end with a hyphen: %q", k, value))
	}
	return
}

func validateElbNamePrefix(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if !regexp.MustCompile(`^[0-9A-Za-z-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"only alphanumeric characters and hyphens allowed in %q: %q",
			k, value))
	}
	if len(value) > 6 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 6 characters: %q", k, value))
	}
	if regexp.MustCompile(`^-`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot begin with a hyphen: %q", k, value))
	}
	return
}

func validateAwsAccountId(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	// http://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html
	pattern := `^\d{12}$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q doesn't look like AWS Account ID (exactly 12 digits): %q",
			k, value))
	}

	return
}

func validateArn(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if value == "" {
		return
	}

	parsedARN, err := arn.Parse(value)

	if err != nil {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: %s", k, value, err))
		return
	}

	if parsedARN.Partition == "" {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing partition value", k, value))
	} else if !awsPartitionRegexp.MatchString(parsedARN.Partition) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid partition value (expecting to match regular expression: %s)", k, value, awsPartitionRegexpPattern))
	}

	if parsedARN.Region != "" && !awsRegionRegexp.MatchString(parsedARN.Region) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid region value (expecting to match regular expression: %s)", k, value, awsRegionRegexpPattern))
	}

	if parsedARN.AccountID != "" && !awsAccountIDRegexp.MatchString(parsedARN.AccountID) {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: invalid account ID value (expecting to match regular expression: %s)", k, value, awsAccountIDRegexpPattern))
	}

	if parsedARN.Resource == "" {
		errors = append(errors, fmt.Errorf("%q (%s) is an invalid ARN: missing resource value", k, value))
	}

	return
}

func validatePolicyStatementId(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if len(value) > 100 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 100 characters: %q", k, value))
	}

	// http://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html
	pattern := `^[a-zA-Z0-9-_]+$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q doesn't look like a valid statement ID (%q): %q",
			k, pattern, value))
	}

	return
}

// validateCIDRNetworkAddress ensures that the string value is a valid CIDR that
// represents a network address - it adds an error otherwise
func validateCIDRNetworkAddress(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	_, ipnet, err := net.ParseCIDR(value)
	if err != nil {
		errors = append(errors, fmt.Errorf(
			"%q must contain a valid CIDR, got error parsing: %s", k, err))
		return
	}

	if ipnet == nil || value != ipnet.String() {
		errors = append(errors, fmt.Errorf(
			"%q must contain a valid network CIDR, got %q", k, value))
	}

	return
}

func validateHTTPMethod() schema.SchemaValidateFunc {
	return validation.StringInSlice([]string{
		"ANY",
		"DELETE",
		"GET",
		"HEAD",
		"OPTIONS",
		"PATCH",
		"POST",
		"PUT",
	}, false)
}

func validateLogMetricFilterName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if len(value) > 512 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 512 characters: %q", k, value))
	}

	// http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutMetricFilter.html
	pattern := `^[^:*]+$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q isn't a valid log metric name (must not contain colon nor asterisk): %q",
			k, value))
	}

	return
}

func validateLogMetricFilterTransformationName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if len(value) > 255 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 255 characters: %q", k, value))
	}

	// http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_MetricTransformation.html
	pattern := `^[^:*$]*$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q isn't a valid log metric transformation name (must not contain"+
				" colon, asterisk nor dollar sign): %q",
			k, value))
	}

	return
}

func validateLogGroupName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if len(value) > 512 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 512 characters: %q", k, value))
	}

	// http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_CreateLogGroup.html
	pattern := `^[\.\-_/#A-Za-z0-9]+$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q isn't a valid log group name (alphanumeric characters, underscores,"+
				" hyphens, slashes, hash signs and dots are allowed): %q",
			k, value))
	}

	return
}

func validateLogGroupNamePrefix(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)

	if len(value) > 483 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 483 characters: %q", k, value))
	}

	// http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_CreateLogGroup.html
	pattern := `^[\.\-_/#A-Za-z0-9]+$`
	if !regexp.MustCompile(pattern).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q isn't a valid log group name (alphanumeric characters, underscores,"+
				" hyphens, slashes, hash signs and dots are allowed): %q",
			k, value))
	}

	return
}

func validateAccountAlias(v interface{}, k string) (ws []string, es []error) {
	val := v.(string)

	if (len(val) < 3) || (len(val) > 63) {
		es = append(es, fmt.Errorf("%q must contain from 3 to 63 alphanumeric characters or hyphens", k))
	}
	if !regexp.MustCompile("^[a-z0-9][a-z0-9-]+$").MatchString(val) {
		es = append(es, fmt.Errorf("%q must start with an alphanumeric character and only contain lowercase alphanumeric characters and hyphens", k))
	}
	if strings.Contains(val, "--") {
		es = append(es, fmt.Errorf("%q must not contain consecutive hyphens", k))
	}
	if strings.HasSuffix(val, "-") {
		es = append(es, fmt.Errorf("%q must not end in a hyphen", k))
	}
	return
}

func validateIamRolePolicyName(v interface{}, k string) (ws []string, errors []error) {
	// https://github.com/boto/botocore/blob/2485f5c/botocore/data/iam/2010-05-08/service-2.json#L8291-L8296
	value := v.(string)
	if len(value) > 128 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 128 characters", k))
	}
	if !regexp.MustCompile(`^[\w+=,.@-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(`%q must match [\w+=,.@-]`, k))
	}
	return
}

func validateIamRolePolicyNamePrefix(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if len(value) > 100 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 100 characters", k))
	}
	if !regexp.MustCompile(`^[\w+=,.@-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(`%q must match [\w+=,.@-]`, k))
	}
	return
}

func validateAwsKmsName(v interface{}, k string) (ws []string, es []error) {
	value := v.(string)
	if !regexp.MustCompile(`^(alias\/)[a-zA-Z0-9:/_-]+$`).MatchString(value) {
		es = append(es, fmt.Errorf(
			"%q must begin with 'alias/' and be comprised of only [a-zA-Z0-9:/_-]", k))
	}
	return
}

func validateAwsKmsGrantName(v interface{}, k string) (ws []string, es []error) {
	value := v.(string)

	if len(value) > 256 {
		es = append(es, fmt.Errorf("%s can not be greater than 256 characters", k))
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9:/_-]+$`).MatchString(value) {
		es = append(es, fmt.Errorf("%s must only contain [a-zA-Z0-9:/_-]", k))
	}

	return
}

func validateKmsKey(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	arnPrefixPattern := `arn:[^:]+:kms:[^:]+:[^:]+:`
	keyIdPattern := "[A-Za-z0-9-]+"
	keyArnPattern := arnPrefixPattern + "key/" + keyIdPattern
	aliasNamePattern := "alias/[a-zA-Z0-9:/_-]+"
	aliasArnPattern := arnPrefixPattern + aliasNamePattern
	if !regexp.MustCompile(fmt.Sprintf("^%s$", keyIdPattern)).MatchString(value) &&
		!regexp.MustCompile(fmt.Sprintf("^%s$", keyArnPattern)).MatchString(value) &&
		!regexp.MustCompile(fmt.Sprintf("^%s$", aliasNamePattern)).MatchString(value) &&
		!regexp.MustCompile(fmt.Sprintf("^%s$", aliasArnPattern)).MatchString(value) {
		errors = append(errors, fmt.Errorf("%q must be one of the following patterns: %s, %s, %s or %s", k, keyIdPattern, keyArnPattern, aliasNamePattern, aliasArnPattern))
	}
	return
}

func validateLbTargetGroupName(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	if len(value) > 32 {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than 32 characters", k))
	}
	if !regexp.MustCompile(`^[0-9A-Za-z-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"only alphanumeric characters and hyphens allowed in %q", k))
	}
	if regexp.MustCompile(`^-`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot begin with a hyphen", k))
	}
	if regexp.MustCompile(`-$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot end with a hyphen", k))
	}
	return
}

func validateLbTargetGroupNamePrefix(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	prefixMaxLength := 32 - resource.UniqueIDSuffixLength
	if len(value) > prefixMaxLength {
		errors = append(errors, fmt.Errorf(
			"%q cannot be longer than %d characters", k, prefixMaxLength))
	}
	if !regexp.MustCompile(`^[0-9A-Za-z-]+$`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"only alphanumeric characters and hyphens allowed in %q", k))
	}
	if regexp.MustCompile(`^-`).MatchString(value) {
		errors = append(errors, fmt.Errorf(
			"%q cannot begin with a hyphen", k))
	}
	return
}
