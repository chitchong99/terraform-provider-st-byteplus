package byteplus

import (
	"context"
	"os"

	"github.com/byteplus-sdk/byteplus-go-sdk-v2/service/iam"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Wrapper of AliCloud client
type byteplusClients struct {
	iamClient *iam.IAM
}

// Ensure the implementation satisfies the expected interfaces
var (
	_ provider.Provider = &byteplusProvider{}
)

// New is a helper function to simplify provider server
func New() provider.Provider {
	return &byteplusProvider{}
}

type byteplusProvider struct{}

type byteplusProviderModel struct {
	Region    types.String `tfsdk:"region"`
	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
}

// Metadata returns the provider type name.
func (p *byteplusProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "st-byteplus"
}

// Schema defines the provider-level schema for configuration data.
func (p *byteplusProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The BytePlus Cloud provider is used to interact with the many resources supported by BytePlus Cloud. " +
			"The provider needs to be configured with the proper credentials before it can be used.",
		Attributes: map[string]schema.Attribute{
			"region": schema.StringAttribute{
				Description: "The Region for BytePlus Provider. May also be provided via BYTEPLUS_REGION environment variable.",
				Optional:    true,
			},
			"access_key": schema.StringAttribute{
				Description: "The Access Key for BytePlus Provider. May also be provided via BYTEPLUS_ACCESS_KEY environment variable.",
				Required:    true,
			},
			"secret_key": schema.StringAttribute{
				Description: "The Secret Key for BytePlus Provider. May also be provided via BYTEPLUS_SECRET_KEY environment variable.",
				Required:    true,
			},
		},
	}
}

// Configure prepares a BytePlus API client for data sources and resources.
func (p *byteplusProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config byteplusProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.
	if config.Region.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Unknown BytePlus region",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API region. Set the value statically in the configuration, or use the BYTEPLUS_REGION environment variable.",
		)
	}

	if config.AccessKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("access_key"),
			"Unknown BytePlus access key",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API access key. Set the value statically in the configuration, or use the BYTEPLUS_ACCESS_KEY environment variable.",
		)
	}

	if config.SecretKey.IsUnknown() { //TODO: cannot detect access key and secret key using terraform plan
		resp.Diagnostics.AddAttributeError(
			path.Root("secret_key"),
			"Unknown BytePlus secret key",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API secret key. Set the value statically in the configuration, or use the BYTEPLUS_SECRET_KEY environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.
	region := os.Getenv("BYTEPLUS_REGION")
	accessKey := os.Getenv("BYTEPLUS_ACCESS_KEY")
	secretKey := os.Getenv("BYTEPLUS_SECRET_KEY")

	if !config.Region.IsNull() {
		region = config.Region.ValueString()
	}

	if !config.AccessKey.IsNull() {
		accessKey = config.AccessKey.ValueString()
	}

	if !config.SecretKey.IsNull() {
		secretKey = config.SecretKey.ValueString()
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.
	if region == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Unknown BytePlus region",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API region. Set the value statically in the configuration, or use the BYTEPLUS_REGION environment variable.",
		)
	}

	if accessKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("access_key"),
			"Unknown BytePlus access key",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API access key. Set the value statically in the configuration, or use the BYTEPLUS_ACCESS_KEY environment variable.",
		)
	}

	if secretKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("secret_key"),
			"Unknown BytePlus secret key",
			"The provider cannot create the BytePlus API client as there is an unknown configuration value for the"+
				"BytePlus API secret key. Set the value statically in the configuration, or use the BYTEPLUS_SECRET_KEY environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

func (p *byteplusProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *byteplusProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewIamPolicyResource,
	}

}
