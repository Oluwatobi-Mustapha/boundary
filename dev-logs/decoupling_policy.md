
Entry: Decoupling Policy Logic from AWS Side-Effects.

Note: "Decided to keep the PolicyEngine 'pure.' We are implementing an AWS Adapter pattern. The Engine will receive an 'AWSAccountContext' object containing pre-fetched facts (Tags, OU IDs) rather than calling boto3 directly. This ensures the engine is fast, testable, and deterministic."

Entry: Implementing Target Selection Logic.

Note: "Added _match_target helper. Supports both OU-based hierarchy matching and Tag-based attribute matching. Using short-circuiting logic (any()) for performance."

Entry: Implementing Target Resolution.

Note: "Integrated AWSAccountContext into the evaluation loop. Added _match_target to support hierarchical (OU) and attribute-based (Tag) authorization."