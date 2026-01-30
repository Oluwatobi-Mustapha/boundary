Action: Update docs/DEVLOG.md.

Entry: Decoupling Policy Logic from AWS Side-Effects.

Note: "Decided to keep the PolicyEngine 'pure.' We are implementing an AWS Adapter pattern. The Engine will receive an 'AWSAccountContext' object containing pre-fetched facts (Tags, OU IDs) rather than calling boto3 directly. This ensures the engine is fast, testable, and deterministic."