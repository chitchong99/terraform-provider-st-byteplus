package byteplus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/byteplus-sdk/byteplus-go-sdk-v2/byteplus"
	"github.com/byteplus-sdk/byteplus-go-sdk-v2/byteplus/bytepluserr"
	"github.com/byteplus-sdk/byteplus-go-sdk-v2/service/iam"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const maxLength = 6144

var (
	_ resource.Resource              = &iamPolicyResource{}
	_ resource.ResourceWithConfigure = &iamPolicyResource{}
	//_ resource.ResourceWithImportState = &iamPolicyResource{}
)

func NewIamPolicyResource() resource.Resource {
	return &iamPolicyResource{}
}

type iamPolicyResource struct {
	client *iam.IAM
}

type iamPolicyResourceModel struct {
	AttachedPolicies types.List   `tfsdk:"attached_policies"`
	Policies         types.List   `tfsdk:"policies"`
	UserName         types.String `tfsdk:"user_name"`
}

type policyDetail struct {
	PolicyName     types.String `tfsdk:"policy_name"`
	PolicyDocument types.String `tfsdk:"policy_document"`
}

func (r *iamPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_policy"
}

func (r *iamPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a IAM Policy resource that manages policy content " +
			"exceeding character limits by splitting it into smaller segments. " +
			"These segments are combined to form a complete policy attached to " +
			"the user. However, the policy that exceed the maximum length of a " +
			"policy, they will be attached directly to the user.",
		Attributes: map[string]schema.Attribute{
			"attached_policies": schema.ListAttribute{
				Description: "The IAM policies to attach to the user.",
				Required:    true,
				ElementType: types.StringType,
			},
			"policies": schema.ListNestedAttribute{
				Description: "A list of policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"policy_name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"policy_document": schema.StringAttribute{
							Description: "The policy document of the IAM policy.",
							Computed:    true,
						},
					},
				},
			},
			"user_name": schema.StringAttribute{
				Description: "The name of the IAM user that attached to the policy.",
				Required:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *iamPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(byteplusClients).iamClient
}

// Create implements resource.Resource.
func (r *iamPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan *iamPolicyResourceModel
	getPlanDiags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.createPolicy(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Create the Policy.",
			err.Error(),
		)
		return
	}

	state := &iamPolicyResourceModel{}
	state.AttachedPolicies = plan.AttachedPolicies
	state.Policies = types.ListValueMust(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
		},
		policy,
	)
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(state); err != nil { //TODO: missing attachuserpolicy
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	readPolicyDiags := r.readPolicy(state)
	resp.Diagnostics.Append(readPolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state *iamPolicyResourceModel
	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	readPolicyDiags := r.readPolicy(state)
	resp.Diagnostics.Append(readPolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	listPoliciesForUser := func() error {
		listPoliciesForUserRequest := &iam.ListAttachedUserPoliciesInput{
			UserName: byteplus.String(state.UserName.ValueString()),
		}

		_, err := r.client.ListAttachedUserPolicies(listPoliciesForUserRequest) //TODO: missing attached user policies
		if err != nil {
			handleAPIError(err)
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(listPoliciesForUser, reconnectBackoff)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Read Users for Group",
			err.Error(),
		)
		return
	}

	// This state will be using to compare with the current state.
	var oriState *iamPolicyResourceModel
	getOriStateDiags := req.State.Get(ctx, &oriState)
	resp.Diagnostics.Append(getOriStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(state.Policies.Elements()) != len(oriState.Policies.Elements()) {
		resp.Diagnostics.AddWarning("Combined policies not found.", "The combined policies attached to the user may be deleted due to human mistake or API error.")
		state.AttachedPolicies = types.ListNull(types.StringType)
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update implements resource.Resource.
func (r *iamPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *iamPolicyResourceModel
	getPlanDiags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(getPlanDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	getStateDiags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(getStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyDiags := r.removePolicy(state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.createPolicy(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Update the Policy.",
			err.Error(),
		)
		return
	}

	state.AttachedPolicies = plan.AttachedPolicies
	state.Policies = types.ListValueMust(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
		},
		policy,
	)
	state.UserName = plan.UserName

	if err := r.attachPolicyToUser(state); err != nil { //TODO: HAVENT IMPLEMENT
		resp.Diagnostics.AddError(
			"[API ERROR] Failed to Attach Policy to User.",
			err.Error(),
		)
		return
	}

	readPolicyDiags := r.readPolicy(state)
	resp.Diagnostics.Append(readPolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	setStateDiags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete implements resource.Resource.
func (r *iamPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state *iamPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	removePolicyDiags := r.removePolicy(state)
	resp.Diagnostics.Append(removePolicyDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *iamPolicyResource) createPolicy(plan *iamPolicyResourceModel) (policiesList []attr.Value, err error) {
	combinedPolicyStatements, notCombinedPolicies, err := r.getPolicyDocument(plan)
	if err != nil {
		return nil, err
	}

	createPolicy := func() error {
		for i, policy := range combinedPolicyStatements {
			policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

			createPolicyRequest := &iam.CreatePolicyInput{
				PolicyName:     byteplus.String(policyName),
				PolicyDocument: byteplus.String(policy),
			}

			if _, err := r.client.CreatePolicy(createPolicyRequest); err != nil {
				handleAPIError(err)
			}
		}

		return nil
	}

	for i, policies := range combinedPolicyStatements {
		policyName := plan.UserName.ValueString() + "-" + strconv.Itoa(i+1)

		policyObj := types.ObjectValueMust(
			map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
			map[string]attr.Value{
				"policy_name":     types.StringValue(policyName),
				"policy_document": types.StringValue(policies),
			},
		)
		policiesList = append(policiesList, policyObj)
	}

	// These policies will be attached directly to the user since splitting the
	// policy "statement" will be hitting the limitation of "maximum number of
	// attached policies" easily.
	for _, policy := range notCombinedPolicies {
		policyObj := types.ObjectValueMust(
			map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
			map[string]attr.Value{
				"policy_name":     types.StringValue(policy.policyName),
				"policy_document": types.StringValue(policy.policyDocument),
			},
		)
		policiesList = append(policiesList, policyObj)
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	return policiesList, backoff.Retry(createPolicy, reconnectBackoff)
}

func (r *iamPolicyResource) readPolicy(state *iamPolicyResourceModel) diag.Diagnostics {
	policyDetailsState := []*policyDetail{}
	getPolicyResponse := &iam.GetPolicyOutput{}

	var err error
	getPolicy := func() error {
		data := make(map[string]string)

		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			getPolicyRequest := iam.GetPolicyInput{
				PolicyName: byteplus.String(data["policy_name"]),
				PolicyType: byteplus.String("Custom"),
			}

			getPolicyResponse, err = r.client.GetPolicy(&getPolicyRequest)
			if err != nil {
				handleAPIError(err)
			}

			// Sometimes combined policies may be removed accidentally by human mistake or API error.
			if getPolicyResponse != nil && getPolicyResponse.Policy != nil {
				if getPolicyResponse.Policy.PolicyName != nil && *getPolicyResponse.Policy.PolicyDocument != "" {
					policyDetail := policyDetail{
						PolicyName:     types.StringValue(*getPolicyResponse.Policy.PolicyName),
						PolicyDocument: types.StringValue(*getPolicyResponse.Policy.PolicyDocument),
					}
					policyDetailsState = append(policyDetailsState, &policyDetail)
				}
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err = backoff.Retry(getPolicy, reconnectBackoff)
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"[API ERROR] Failed to Read Policy.",
				err.Error(),
			),
		}
	}

	policyDetails := []attr.Value{}
	for _, policy := range policyDetailsState {
		policyDetails = append(policyDetails, types.ObjectValueMust(
			map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
			map[string]attr.Value{
				"policy_name":     types.StringValue(policy.PolicyName.ValueString()),
				"policy_document": types.StringValue(policy.PolicyDocument.ValueString()),
			},
		))
	}
	state.Policies = types.ListValueMust(
		types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"policy_name":     types.StringType,
				"policy_document": types.StringType,
			},
		},
		policyDetails,
	)
	return nil
}

func (r *iamPolicyResource) removePolicy(state *iamPolicyResourceModel) diag.Diagnostics {
	data := make(map[string]string)

	removePolicy := func() error {
		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			detachPolicyFromUserRequest := &iam.DetachUserPolicyInput{
				PolicyType: byteplus.String("Custom"),
				PolicyName: byteplus.String(data["policy_name"]),
				UserName:   byteplus.String(state.UserName.ValueString()),
			}

			deletePolicyRequest := &iam.DeletePolicyInput{
				PolicyName: byteplus.String(data["policy_name"]),
			}

			if _, err := r.client.DetachUserPolicy(detachPolicyFromUserRequest); err != nil { //TODO: missing detach policy
				handleAPIError(err)
			}

			if _, err := r.client.DeletePolicy(deletePolicyRequest); err != nil {
				handleAPIError(err)
			}
		}

		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	err := backoff.Retry(removePolicy, reconnectBackoff)
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"[API ERROR] Failed to Delete Policy",
				err.Error(),
			),
		}
	}

	return nil
}

type simplePolicy struct {
	policyName     string
	policyDocument string
}

func (r *iamPolicyResource) getPolicyDocument(plan *iamPolicyResourceModel) (finalPolicyDocument []string, excludedPolicy []simplePolicy, err error) {
	policyName := ""
	currentLength := 0
	currentPolicyDocument := ""
	appendedPolicyDocument := make([]string, 0)

	var getPolicyResponse *iam.GetPolicyOutput

	for i, policy := range plan.AttachedPolicies.Elements() {
		policyName = policy.String()
		getPolicyRequest := &iam.GetPolicyInput{
			PolicyType: byteplus.String("Custom"),
			PolicyName: byteplus.String(trimStringQuotes(policyName)),
		}

		getPolicy := func() error {
			for {
				var err error
				getPolicyResponse, err = r.client.GetPolicy(getPolicyRequest)

				if err == nil {
					return nil
				}

				if *getPolicyResponse.Policy.PolicyType == "System" {
					return backoff.Permanent(err)
				}

				// If returns PolicyType "Custom", but SDK error occurs,
				// Assumes PolicyType is "System"
				if _, ok := err.(bytepluserr.Error); ok && *getPolicyResponse.Policy.PolicyType == "Custom" {
					getPolicyResponse.Policy.PolicyType = byteplus.String("System")
					continue
				}
			}
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 30 * time.Second
		backoff.Retry(getPolicy, reconnectBackoff)

		if getPolicyResponse != nil && *getPolicyResponse.Policy.PolicyDocument != "" {
			tempPolicyDocument, err := url.QueryUnescape(*getPolicyResponse.Policy.PolicyDocument)
			if err != nil {
				return nil, nil, err
			}

			skipCombinePolicy := false
			// If the policy itself have more than 6144 characters, then skip the combine
			// policy part since splitting the policy "statement" will be hitting the
			// limitation of "maximum number of attached policies" easily.
			if len(tempPolicyDocument) > maxLength {
				excludedPolicy = append(excludedPolicy, simplePolicy{
					policyName:     policyName,
					policyDocument: tempPolicyDocument,
				})
				skipCombinePolicy = true
			}

			if !skipCombinePolicy {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(tempPolicyDocument), &data); err != nil {
					return nil, nil, err
				}

				statementArr := data["Statement"].([]interface{})
				statementBytes, err := json.Marshal(statementArr)
				if err != nil {
					return nil, nil, err
				}

				finalStatement := strings.Trim(string(statementBytes), "[]")

				currentLength += len(finalStatement)

				// Before further proceeding the current policy, we need to add a number of 30 to simulate the total length of completed policy to check whether it is already execeeded the max character length of 6144.
				// Number of 30 indicates the character length of neccessary policy keyword such as "Version" and "Statement" and some JSON symbols ({}, [])
				if (currentLength + 30) > maxLength {
					lastCommaIndex := strings.LastIndex(currentPolicyDocument, ",")
					if lastCommaIndex >= 0 {
						currentPolicyDocument = currentPolicyDocument[:lastCommaIndex] + currentPolicyDocument[lastCommaIndex+1:]
					}

					appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
					currentPolicyDocument = finalStatement + ","
					currentLength = len(finalStatement)
				} else {
					currentPolicyDocument += finalStatement + ","
				}
			}

			if i == len(plan.AttachedPolicies.Elements())-1 && (currentLength+30) <= maxLength {
				lastCommaIndex := strings.LastIndex(currentPolicyDocument, ",")
				if lastCommaIndex >= 0 {
					currentPolicyDocument = currentPolicyDocument[:lastCommaIndex] + currentPolicyDocument[lastCommaIndex+1:]
				}
				appendedPolicyDocument = append(appendedPolicyDocument, currentPolicyDocument)
			}
		}
	}

	if len(appendedPolicyDocument) > 0 {
		for _, policy := range appendedPolicyDocument {
			finalPolicyDocument = append(finalPolicyDocument, fmt.Sprintf(`{"Version":"1","Statement":[%v]}`, policy))
		}
	}

	return finalPolicyDocument, excludedPolicy, nil
}

func (r *iamPolicyResource) attachPolicyToUser(state *iamPolicyResourceModel) (err error) {
	data := make(map[string]string)

	attachPolicyToUser := func() error {
		for _, policies := range state.Policies.Elements() {
			json.Unmarshal([]byte(policies.String()), &data)

			attachPolicyToUserRequest := &iam.AttachUserPolicyInput{
				PolicyType: byteplus.String("Custom"),
				PolicyName: byteplus.String(data["policy_name"]),
				UserName:   byteplus.String(state.UserName.ValueString()),
			}

			if _, err := r.client.AttachUserPolicy(attachPolicyToUserRequest); err != nil {
				return handleAPIError(err)
			}
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 30 * time.Second
	return backoff.Retry(attachPolicyToUser, reconnectBackoff)
}

func handleAPIError(err error) error {
	if _t, ok := err.(bytepluserr.Error); ok {
		if isAbleToRetry(_t.Code()) {
			return err
		} else {
			return backoff.Permanent(err)
		}
	} else {
		return err
	}
}
