package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// References:
// - https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization
// - https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature
// - https://learn.microsoft.com/en-us/azure/communication-services/concepts/voice-video-calling/calling-sdk-credentials
// - https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure#access-keys
func AzureServiceBusSharedAccessKey() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-service-bus-shared-access-key",
		Description: "Identified an Azure Service Bus, Event Hubs, or Notification Hubs Shared Access Key, which may compromise message bus and event streaming infrastructure.",
		Regex:       regexp.MustCompile(`SharedAccessKey=([a-zA-Z0-9+/]{40,100}={0,2})`),
		Keywords: []string{
			"SharedAccessKey=",
		},
	}

	tps := []string{
		`Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=8nK2pQx7RtL9vWc4YhB3mZf6sD1aE5uG8jN0qX2wR7tV4nK8LpZ3r`, // gitleaks:allow
		`endpoint=https://contoso.servicebus.windows.net/contoso;SharedAccessKeyName=policy;SharedAccessKey=mT5vW2cR9hB4fS1aE7uG3jN6qX0wR8tV4bH5nK4pL9zD1sY3r`,              // gitleaks:allow
	}
	fps := []string{
		`SharedAccessKeyName=RootManageSharedAccessKey;`,
		`SharedAccessKey=short`,
		`Endpoint=sb://contoso.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=`,
	}
	return utils.Validate(r, tps, fps)
}

func AzureCommunicationServicesKey() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-communication-services-key",
		Description: "Identified an Azure Communication Services connection string access key, which may compromise calling, chat, and SMS infrastructure.",
		Regex:       regexp.MustCompile(`accesskey=([a-zA-Z0-9+/]{40,200}={0,2})`),
		Keywords: []string{
			".communication.azure.com",
			"accesskey=",
		},
	}

	tps := []string{
		`endpoint=https://contoso.communication.azure.com/;accesskey=kP9mZ3qR7vWc4YhB2nTf6sD1aE5uG8jN0qX2wR7tV4bH5nK8LpZ3rT6`, // gitleaks:allow
		`Endpoint=https://contoso.communication.azure.com/;accesskey=rT2vW9cR4hB7fS3aE1uG5jN8qX6wR0tV4bH2nK9pL3zD7sY5mZ`,      // gitleaks:allow
	}
	fps := []string{
		`endpoint=https://contoso.communication.azure.com/;accesskey=short`,
		`aws_secret_access_key=AKIAIOSFODNN7EXAMPLEKEY`,
	}
	return utils.Validate(r, tps, fps)
}

func AzureRedisCacheKey() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-redis-cache-key",
		Description: "Identified an Azure Cache for Redis access key, which may compromise cached data and session stores.",
		Regex:       regexp.MustCompile(`password=([a-zA-Z0-9+/]{20,200}={0,2})`),
		Keywords: []string{
			".redis.cache.windows.net",
		},
	}

	tps := []string{
		`contoso.redis.cache.windows.net:6380,password=8nK2pQx7RtL9vWc4YhB3mZf6sD1aE5uG8jN0qX2wR7tV4nK8Lp,ssl=True`, // gitleaks:allow
		`contoso.redis.cache.windows.net:6380,password=mT5vW2cR9hB4fS1aE7uG3jN6qX0wR8tV4bH5nK4pL9zD1sY3r,ssl=True`,  // gitleaks:allow
	}
	fps := []string{
		`contoso.redis.cache.windows.net:6380,password=short,ssl=True`,
		`postgres://user:password@localhost:5432/db`,
	}
	return utils.Validate(r, tps, fps)
}
