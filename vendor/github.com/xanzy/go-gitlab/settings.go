//
// Copyright 2017, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package gitlab

import "time"

// SettingsService handles communication with the application SettingsService
// related methods of the GitLab API.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/settings.html
type SettingsService struct {
	client *Client
}

// Settings represents the GitLab application settings.
//
// GitLab API docs: https://docs.gitlab.com/ce/api/settings.html
type Settings struct {
	ID                                  int               `json:"id"`
	CreatedAt                           *time.Time        `json:"created_at"`
	UpdatedAt                           *time.Time        `json:"updated_at"`
	AdminNotificationEmail              string            `json:"admin_notification_email"`
	AfterSignOutPath                    string            `json:"after_sign_out_path"`
	AfterSignUpText                     string            `json:"after_sign_up_text"`
	AkismetAPIKey                       string            `json:"akismet_api_key"`
	AkismetEnabled                      bool              `json:"akismet_enabled"`
	CircuitbreakerAccessRetries         int               `json:"circuitbreaker_access_retries"`
	CircuitbreakerBackoffThreshold      int               `json:"circuitbreaker_backoff_threshold"`
	CircuitbreakerFailureCountThreshold int               `json:"circuitbreaker_failure_count_threshold"`
	CircuitbreakerFailureResetTime      int               `json:"circuitbreaker_failure_reset_time"`
	CircuitbreakerFailureWaitTime       int               `json:"circuitbreaker_failure_wait_time"`
	CircuitbreakerStorageTimeout        int               `json:"circuitbreaker_storage_timeout"`
	ClientsideSentryDSN                 string            `json:"clientside_sentry_dsn"`
	ClientsideSentryEnabled             bool              `json:"clientside_sentry_enabled"`
	ContainerRegistryTokenExpireDelay   int               `json:"container_registry_token_expire_delay"`
	DefaultArtifactsExpireIn            string            `json:"default_artifacts_expire_in"`
	DefaultBranchProtection             int               `json:"default_branch_protection"`
	DefaultGroupVisibility              string            `json:"default_group_visibility"`
	DefaultProjectVisibility            string            `json:"default_project_visibility"`
	DefaultProjectsLimit                int               `json:"default_projects_limit"`
	DefaultSnippetVisibility            string            `json:"default_snippet_visibility"`
	DisabledOauthSignInSources          []string          `json:"disabled_oauth_sign_in_sources"`
	DomainBlacklistEnabled              bool              `json:"domain_blacklist_enabled"`
	DomainBlacklist                     []string          `json:"domain_blacklist"`
	DomainWhitelist                     []string          `json:"domain_whitelist"`
	DSAKeyRestriction                   int               `json:"dsa_key_restriction"`
	ECDSAKeyRestriction                 int               `json:"ecdsa_key_restriction"`
	Ed25519KeyRestriction               int               `json:"ed25519_key_restriction"`
	EmailAuthorInBody                   bool              `json:"email_author_in_body"`
	EnabledGitAccessProtocol            string            `json:"enabled_git_access_protocol"`
	GravatarEnabled                     bool              `json:"gravatar_enabled"`
	HelpPageHideCommercialContent       bool              `json:"help_page_hide_commercial_content"`
	HelpPageSupportURL                  string            `json:"help_page_support_url"`
	HomePageURL                         string            `json:"home_page_url"`
	HousekeepingBitmapsEnabled          bool              `json:"housekeeping_bitmaps_enabled"`
	HousekeepingEnabled                 bool              `json:"housekeeping_enabled"`
	HousekeepingFullRepackPeriod        int               `json:"housekeeping_full_repack_period"`
	HousekeepingGcPeriod                int               `json:"housekeeping_gc_period"`
	HousekeepingIncrementalRepackPeriod int               `json:"housekeeping_incremental_repack_period"`
	HTMLEmailsEnabled                   bool              `json:"html_emails_enabled"`
	ImportSources                       []string          `json:"import_sources"`
	KodingEnabled                       bool              `json:"koding_enabled"`
	KodingURL                           string            `json:"koding_url"`
	MaxArtifactsSize                    int               `json:"max_artifacts_size"`
	MaxAttachmentSize                   int               `json:"max_attachment_size"`
	MaxPagesSize                        int               `json:"max_pages_size"`
	MetricsEnabled                      bool              `json:"metrics_enabled"`
	MetricsHost                         string            `json:"metrics_host"`
	MetricsMethodCallThreshold          int               `json:"metrics_method_call_threshold"`
	MetricsPacketSize                   int               `json:"metrics_packet_size"`
	MetricsPoolSize                     int               `json:"metrics_pool_size"`
	MetricsPort                         int               `json:"metrics_port"`
	MetricsSampleInterval               int               `json:"metrics_sample_interval"`
	MetricsTimeout                      int               `json:"metrics_timeout"`
	PasswordAuthenticationEnabledForWeb bool              `json:"password_authentication_enabled_for_web"`
	PasswordAuthenticationEnabledForGit bool              `json:"password_authentication_enabled_for_git"`
	PerformanceBarAllowedGroupID        string            `json:"performance_bar_allowed_group_id"`
	PerformanceBarEnabled               bool              `json:"performance_bar_enabled"`
	PlantumlEnabled                     bool              `json:"plantuml_enabled"`
	PlantumlURL                         string            `json:"plantuml_url"`
	PollingIntervalMultiplier           float64           `json:"polling_interval_multiplier"`
	ProjectExportEnabled                bool              `json:"project_export_enabled"`
	PrometheusMetricsEnabled            bool              `json:"prometheus_metrics_enabled"`
	RecaptchaEnabled                    bool              `json:"recaptcha_enabled"`
	RecaptchaPrivateKey                 string            `json:"recaptcha_private_key"`
	RecaptchaSiteKey                    string            `json:"recaptcha_site_key"`
	RepositoryChecksEnabled             bool              `json:"repository_checks_enabled"`
	RepositoryStorages                  []string          `json:"repository_storages"`
	RequireTwoFactorAuthentication      bool              `json:"require_two_factor_authentication"`
	RestrictedVisibilityLevels          []VisibilityValue `json:"restricted_visibility_levels"`
	RsaKeyRestriction                   int               `json:"rsa_key_restriction"`
	SendUserConfirmationEmail           bool              `json:"send_user_confirmation_email"`
	SentryDSN                           string            `json:"sentry_dsn"`
	SentryEnabled                       bool              `json:"sentry_enabled"`
	SessionExpireDelay                  int               `json:"session_expire_delay"`
	SharedRunnersEnabled                bool              `json:"shared_runners_enabled"`
	SharedRunnersText                   string            `json:"shared_runners_text"`
	SidekiqThrottlingEnabled            bool              `json:"sidekiq_throttling_enabled"`
	SidekiqThrottlingFactor             float64           `json:"sidekiq_throttling_factor"`
	SidekiqThrottlingQueues             []string          `json:"sidekiq_throttling_queues"`
	SignInText                          string            `json:"sign_in_text"`
	SignupEnabled                       bool              `json:"signup_enabled"`
	TerminalMaxSessionTime              int               `json:"terminal_max_session_time"`
	TwoFactorGracePeriod                int               `json:"two_factor_grace_period"`
	UniqueIPsLimitEnabled               bool              `json:"unique_ips_limit_enabled"`
	UniqueIPsLimitPerUser               int               `json:"unique_ips_limit_per_user"`
	UniqueIPsLimitTimeWindow            int               `json:"unique_ips_limit_time_window"`
	UsagePingEnabled                    bool              `json:"usage_ping_enabled"`
	UserDefaultExternal                 bool              `json:"user_default_external"`
	UserOauthApplications               bool              `json:"user_oauth_applications"`
	VersionCheckEnabled                 bool              `json:"version_check_enabled"`
}

func (s Settings) String() string {
	return Stringify(s)
}

// GetSettings gets the current application settings.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/settings.html#get-current-application.settings
func (s *SettingsService) GetSettings(options ...OptionFunc) (*Settings, *Response, error) {
	req, err := s.client.NewRequest("GET", "application/settings", nil, options)
	if err != nil {
		return nil, nil, err
	}

	as := new(Settings)
	resp, err := s.client.Do(req, as)
	if err != nil {
		return nil, resp, err
	}

	return as, resp, err
}

// UpdateSettingsOptions represents the available UpdateSettings() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/settings.html#change-application.settings
type UpdateSettingsOptions struct {
	AdminNotificationEmail              *string           `url:"admin_notification_email,omitempty" json:"admin_notification_email,omitempty"`
	AfterSignOutPath                    *string           `url:"after_sign_out_path,omitempty" json:"after_sign_out_path,omitempty"`
	AfterSignUpText                     *string           `url:"after_sign_up_text,omitempty" json:"after_sign_up_text,omitempty"`
	AkismetAPIKey                       *string           `url:"akismet_api_key,omitempty" json:"akismet_api_key,omitempty"`
	AkismetEnabled                      *bool             `url:"akismet_enabled,omitempty" json:"akismet_enabled,omitempty"`
	CircuitbreakerAccessRetries         *int              `url:"circuitbreaker_access_retries,omitempty" json:"circuitbreaker_access_retries,omitempty"`
	CircuitbreakerBackoffThreshold      *int              `url:"circuitbreaker_backoff_threshold,omitempty" json:"circuitbreaker_backoff_threshold,omitempty"`
	CircuitbreakerFailureCountThreshold *int              `url:"circuitbreaker_failure_count_threshold,omitempty" json:"circuitbreaker_failure_count_threshold,omitempty"`
	CircuitbreakerFailureResetTime      *int              `url:"circuitbreaker_failure_reset_time,omitempty" json:"circuitbreaker_failure_reset_time,omitempty"`
	CircuitbreakerFailureWaitTime       *int              `url:"circuitbreaker_failure_wait_time,omitempty" json:"circuitbreaker_failure_wait_time,omitempty"`
	CircuitbreakerStorageTimeout        *int              `url:"circuitbreaker_storage_timeout,omitempty" json:"circuitbreaker_storage_timeout,omitempty"`
	ClientsideSentryDSN                 *string           `url:"clientside_sentry_dsn,omitempty" json:"clientside_sentry_dsn,omitempty"`
	ClientsideSentryEnabled             *bool             `url:"clientside_sentry_enabled,omitempty" json:"clientside_sentry_enabled,omitempty"`
	ContainerRegistryTokenExpireDelay   *int              `url:"container_registry_token_expire_delay,omitempty" json:"container_registry_token_expire_delay,omitempty"`
	DefaultArtifactsExpireIn            *string           `url:"default_artifacts_expire_in,omitempty" json:"default_artifacts_expire_in,omitempty"`
	DefaultBranchProtection             *int              `url:"default_branch_protection,omitempty" json:"default_branch_protection,omitempty"`
	DefaultGroupVisibility              *string           `url:"default_group_visibility,omitempty" json:"default_group_visibility,omitempty"`
	DefaultProjectVisibility            *string           `url:"default_project_visibility,omitempty" json:"default_project_visibility,omitempty"`
	DefaultProjectsLimit                *int              `url:"default_projects_limit,omitempty" json:"default_projects_limit,omitempty"`
	DefaultSnippetVisibility            *string           `url:"default_snippet_visibility,omitempty" json:"default_snippet_visibility,omitempty"`
	DisabledOauthSignInSources          []string          `url:"disabled_oauth_sign_in_sources,omitempty" json:"disabled_oauth_sign_in_sources,omitempty"`
	DomainBlacklistEnabled              *bool             `url:"domain_blacklist_enabled,omitempty" json:"domain_blacklist_enabled,omitempty"`
	DomainBlacklist                     []string          `url:"domain_blacklist,omitempty" json:"domain_blacklist,omitempty"`
	DomainWhitelist                     []string          `url:"domain_whitelist,omitempty" json:"domain_whitelist,omitempty"`
	DSAKeyRestriction                   *int              `url:"dsa_key_restriction,omitempty" json:"dsa_key_restriction,omitempty"`
	ECDSAKeyRestriction                 *int              `url:"ecdsa_key_restriction,omitempty" json:"ecdsa_key_restriction,omitempty"`
	Ed25519KeyRestriction               *int              `url:"ed25519_key_restriction,omitempty" json:"ed25519_key_restriction,omitempty"`
	EmailAuthorInBody                   *bool             `url:"email_author_in_body,omitempty" json:"email_author_in_body,omitempty"`
	EnabledGitAccessProtocol            *string           `url:"enabled_git_access_protocol,omitempty" json:"enabled_git_access_protocol,omitempty"`
	GravatarEnabled                     *bool             `url:"gravatar_enabled,omitempty" json:"gravatar_enabled,omitempty"`
	HelpPageHideCommercialContent       *bool             `url:"help_page_hide_commercial_content,omitempty" json:"help_page_hide_commercial_content,omitempty"`
	HelpPageSupportURL                  *string           `url:"help_page_support_url,omitempty" json:"help_page_support_url,omitempty"`
	HomePageURL                         *string           `url:"home_page_url,omitempty" json:"home_page_url,omitempty"`
	HousekeepingBitmapsEnabled          *bool             `url:"housekeeping_bitmaps_enabled,omitempty" json:"housekeeping_bitmaps_enabled,omitempty"`
	HousekeepingEnabled                 *bool             `url:"housekeeping_enabled,omitempty" json:"housekeeping_enabled,omitempty"`
	HousekeepingFullRepackPeriod        *int              `url:"housekeeping_full_repack_period,omitempty" json:"housekeeping_full_repack_period,omitempty"`
	HousekeepingGcPeriod                *int              `url:"housekeeping_gc_period,omitempty" json:"housekeeping_gc_period,omitempty"`
	HousekeepingIncrementalRepackPeriod *int              `url:"housekeeping_incremental_repack_period,omitempty" json:"housekeeping_incremental_repack_period,omitempty"`
	HTMLEmailsEnabled                   *bool             `url:"html_emails_enabled,omitempty" json:"html_emails_enabled,omitempty"`
	ImportSources                       []string          `url:"import_sources,omitempty" json:"import_sources,omitempty"`
	KodingEnabled                       *bool             `url:"koding_enabled,omitempty" json:"koding_enabled,omitempty"`
	KodingURL                           *string           `url:"koding_url,omitempty" json:"koding_url,omitempty"`
	MaxArtifactsSize                    *int              `url:"max_artifacts_size,omitempty" json:"max_artifacts_size,omitempty"`
	MaxAttachmentSize                   *int              `url:"max_attachment_size,omitempty" json:"max_attachment_size,omitempty"`
	MaxPagesSize                        *int              `url:"max_pages_size,omitempty" json:"max_pages_size,omitempty"`
	MetricsEnabled                      *bool             `url:"metrics_enabled,omitempty" json:"metrics_enabled,omitempty"`
	MetricsHost                         *string           `url:"metrics_host,omitempty" json:"metrics_host,omitempty"`
	MetricsMethodCallThreshold          *int              `url:"metrics_method_call_threshold,omitempty" json:"metrics_method_call_threshold,omitempty"`
	MetricsPacketSize                   *int              `url:"metrics_packet_size,omitempty" json:"metrics_packet_size,omitempty"`
	MetricsPoolSize                     *int              `url:"metrics_pool_size,omitempty" json:"metrics_pool_size,omitempty"`
	MetricsPort                         *int              `url:"metrics_port,omitempty" json:"metrics_port,omitempty"`
	MetricsSampleInterval               *int              `url:"metrics_sample_interval,omitempty" json:"metrics_sample_interval,omitempty"`
	MetricsTimeout                      *int              `url:"metrics_timeout,omitempty" json:"metrics_timeout,omitempty"`
	PasswordAuthenticationEnabledForWeb *bool             `url:"password_authentication_enabled_for_web,omitempty" json:"password_authentication_enabled_for_web,omitempty"`
	PasswordAuthenticationEnabledForGit *bool             `url:"password_authentication_enabled_for_git,omitempty" json:"password_authentication_enabled_for_git,omitempty"`
	PerformanceBarAllowedGroupID        *string           `url:"performance_bar_allowed_group_id,omitempty" json:"performance_bar_allowed_group_id,omitempty"`
	PerformanceBarEnabled               *bool             `url:"performance_bar_enabled,omitempty" json:"performance_bar_enabled,omitempty"`
	PlantumlEnabled                     *bool             `url:"plantuml_enabled,omitempty" json:"plantuml_enabled,omitempty"`
	PlantumlURL                         *string           `url:"plantuml_url,omitempty" json:"plantuml_url,omitempty"`
	PollingIntervalMultiplier           *float64          `url:"polling_interval_multiplier,omitempty" json:"polling_interval_multiplier,omitempty"`
	ProjectExportEnabled                *bool             `url:"project_export_enabled,omitempty" json:"project_export_enabled,omitempty"`
	PrometheusMetricsEnabled            *bool             `url:"prometheus_metrics_enabled,omitempty" json:"prometheus_metrics_enabled,omitempty"`
	RecaptchaEnabled                    *bool             `url:"recaptcha_enabled,omitempty" json:"recaptcha_enabled,omitempty"`
	RecaptchaPrivateKey                 *string           `url:"recaptcha_private_key,omitempty" json:"recaptcha_private_key,omitempty"`
	RecaptchaSiteKey                    *string           `url:"recaptcha_site_key,omitempty" json:"recaptcha_site_key,omitempty"`
	RepositoryChecksEnabled             *bool             `url:"repository_checks_enabled,omitempty" json:"repository_checks_enabled,omitempty"`
	RepositoryStorages                  []string          `url:"repository_storages,omitempty" json:"repository_storages,omitempty"`
	RequireTwoFactorAuthentication      *bool             `url:"require_two_factor_authentication,omitempty" json:"require_two_factor_authentication,omitempty"`
	RestrictedVisibilityLevels          []VisibilityValue `url:"restricted_visibility_levels,omitempty" json:"restricted_visibility_levels,omitempty"`
	RsaKeyRestriction                   *int              `url:"rsa_key_restriction,omitempty" json:"rsa_key_restriction,omitempty"`
	SendUserConfirmationEmail           *bool             `url:"send_user_confirmation_email,omitempty" json:"send_user_confirmation_email,omitempty"`
	SentryDSN                           *string           `url:"sentry_dsn,omitempty" json:"sentry_dsn,omitempty"`
	SentryEnabled                       *bool             `url:"sentry_enabled,omitempty" json:"sentry_enabled,omitempty"`
	SessionExpireDelay                  *int              `url:"session_expire_delay,omitempty" json:"session_expire_delay,omitempty"`
	SharedRunnersEnabled                *bool             `url:"shared_runners_enabled,omitempty" json:"shared_runners_enabled,omitempty"`
	SharedRunnersText                   *string           `url:"shared_runners_text,omitempty" json:"shared_runners_text,omitempty"`
	SidekiqThrottlingEnabled            *bool             `url:"sidekiq_throttling_enabled,omitempty" json:"sidekiq_throttling_enabled,omitempty"`
	SidekiqThrottlingFactor             *float64          `url:"sidekiq_throttling_factor,omitempty" json:"sidekiq_throttling_factor,omitempty"`
	SidekiqThrottlingQueues             []string          `url:"sidekiq_throttling_queues,omitempty" json:"sidekiq_throttling_queues,omitempty"`
	SignInText                          *string           `url:"sign_in_text,omitempty" json:"sign_in_text,omitempty"`
	SignupEnabled                       *bool             `url:"signup_enabled,omitempty" json:"signup_enabled,omitempty"`
	TerminalMaxSessionTime              *int              `url:"terminal_max_session_time,omitempty" json:"terminal_max_session_time,omitempty"`
	TwoFactorGracePeriod                *int              `url:"two_factor_grace_period,omitempty" json:"two_factor_grace_period,omitempty"`
	UniqueIPsLimitEnabled               *bool             `url:"unique_ips_limit_enabled,omitempty" json:"unique_ips_limit_enabled,omitempty"`
	UniqueIPsLimitPerUser               *int              `url:"unique_ips_limit_per_user,omitempty" json:"unique_ips_limit_per_user,omitempty"`
	UniqueIPsLimitTimeWindow            *int              `url:"unique_ips_limit_time_window,omitempty" json:"unique_ips_limit_time_window,omitempty"`
	UsagePingEnabled                    *bool             `url:"usage_ping_enabled,omitempty" json:"usage_ping_enabled,omitempty"`
	UserDefaultExternal                 *bool             `url:"user_default_external,omitempty" json:"user_default_external,omitempty"`
	UserOauthApplications               *bool             `url:"user_oauth_applications,omitempty" json:"user_oauth_applications,omitempty"`
	VersionCheckEnabled                 *bool             `url:"version_check_enabled,omitempty" json:"version_check_enabled,omitempty"`
}

// UpdateSettings updates the application settings.
//
// GitLab API docs:
// https://docs.gitlab.com/ce/api/settings.html#change-application.settings
func (s *SettingsService) UpdateSettings(opt *UpdateSettingsOptions, options ...OptionFunc) (*Settings, *Response, error) {
	req, err := s.client.NewRequest("PUT", "application/settings", opt, options)
	if err != nil {
		return nil, nil, err
	}

	as := new(Settings)
	resp, err := s.client.Do(req, as)
	if err != nil {
		return nil, resp, err
	}

	return as, resp, err
}
