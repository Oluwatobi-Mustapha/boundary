import os
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
for path in (SRC, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import boundary_cli  # noqa: E402


def test_derive_instance_arn_from_permission_set_arn():
    permission_set_arn = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-abcdef1234567890"
    assert (
        boundary_cli._derive_instance_arn_from_permission_set_arn(permission_set_arn)
        == "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    )


def test_derive_instance_arn_returns_none_for_invalid_arn():
    assert boundary_cli._derive_instance_arn_from_permission_set_arn("not-an-arn") is None


def test_extract_tfvar_string_reads_nested_map_key(tmp_path):
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(
        """
boundary_secrets = {
  PROD_OU_ID = "ou-1234-abcdef12"
  AWS_SSO_START_URL = "https://d-1234567890.awsapps.com/start"
}
""".strip(),
        encoding="utf-8",
    )

    assert boundary_cli._extract_tfvar_string(str(tfvars), "PROD_OU_ID") == "ou-1234-abcdef12"
    assert (
        boundary_cli._extract_tfvar_string(str(tfvars), "AWS_SSO_START_URL")
        == "https://d-1234567890.awsapps.com/start"
    )
