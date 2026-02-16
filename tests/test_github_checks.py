"""Tests for GitHub compliance check modules (18 tests with mocked PyGithub)."""

import os
import sys
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_org(login="test-org"):
    org = MagicMock()
    org.login = login
    return org


def _mock_repo(name="test-org/test-repo", archived=False, default_branch="main"):
    repo = MagicMock()
    repo.full_name = name
    repo.archived = archived
    repo.default_branch = default_branch
    return repo


# ---------------------------------------------------------------------------
# Branch Protection Tests (3)
# ---------------------------------------------------------------------------

class TestBranchProtectionChecks:
    def test_branch_protection_compliant(self):
        from checks.branch_protection import run_branch_protection_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]

        branch = MagicMock()
        protection = MagicMock()
        reviews = MagicMock()
        reviews.required_approving_review_count = 2
        protection.required_pull_request_reviews = reviews
        protection.required_status_checks = MagicMock()
        branch.get_protection.return_value = protection
        repo.get_branch.return_value = branch

        result = run_branch_protection_checks(org, MagicMock())
        assert result["check"] == "branch_protection"
        assert result["status"] == "pass"

    def test_branch_protection_no_reviews(self):
        from checks.branch_protection import run_branch_protection_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]

        branch = MagicMock()
        protection = MagicMock()
        protection.required_pull_request_reviews = None
        protection.required_status_checks = MagicMock()
        branch.get_protection.return_value = protection
        repo.get_branch.return_value = branch

        result = run_branch_protection_checks(org, MagicMock())
        assert result["failed"] >= 1

    def test_branch_protection_none(self):
        from checks.branch_protection import run_branch_protection_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        repo.get_branch.return_value.get_protection.side_effect = Exception("Not found")

        result = run_branch_protection_checks(org, MagicMock())
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Secret Scanning Tests (2)
# ---------------------------------------------------------------------------

class TestSecretScanningChecks:
    def test_no_open_alerts(self):
        from checks.secret_scanning import run_secret_scanning_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        repo.get_secret_scanning_alerts.return_value = []

        result = run_secret_scanning_checks(org, MagicMock())
        assert result["status"] == "pass"

    def test_open_alerts(self):
        from checks.secret_scanning import run_secret_scanning_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        repo.get_secret_scanning_alerts.return_value = [MagicMock(), MagicMock()]

        result = run_secret_scanning_checks(org, MagicMock())
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Dependabot Tests (2)
# ---------------------------------------------------------------------------

class TestDependabotChecks:
    def test_no_alerts(self):
        from checks.dependabot import run_dependabot_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        repo.get_dependabot_alerts.return_value = []

        result = run_dependabot_checks(org, MagicMock())
        assert result["status"] == "pass"

    def test_critical_alerts(self):
        from checks.dependabot import run_dependabot_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        alert = MagicMock()
        alert.security_vulnerability.severity = "critical"
        repo.get_dependabot_alerts.return_value = [alert]

        result = run_dependabot_checks(org, MagicMock())
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Two-Factor Tests (2)
# ---------------------------------------------------------------------------

class TestTwoFactorChecks:
    def test_2fa_enforced(self):
        from checks.two_factor import run_two_factor_checks
        org = _mock_org()
        org.two_factor_requirement_enabled = True
        org.get_members.return_value = []

        result = run_two_factor_checks(org, MagicMock())
        assert result["status"] == "pass"

    def test_2fa_not_enforced(self):
        from checks.two_factor import run_two_factor_checks
        org = _mock_org()
        org.two_factor_requirement_enabled = False
        org.get_members.return_value = [MagicMock()]

        result = run_two_factor_checks(org, MagicMock())
        assert result["status"] == "fail"
        assert result["failed"] == 2


# ---------------------------------------------------------------------------
# Deploy Keys Tests (2)
# ---------------------------------------------------------------------------

class TestDeployKeysChecks:
    def test_read_only_keys(self):
        from checks.deploy_keys import run_deploy_keys_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        key = MagicMock()
        key.read_only = True
        key.title = "CI key"
        key.id = 1
        repo.get_keys.return_value = [key]

        result = run_deploy_keys_checks(org, MagicMock())
        assert result["status"] == "pass"

    def test_read_write_key(self):
        from checks.deploy_keys import run_deploy_keys_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        key = MagicMock()
        key.read_only = False
        key.title = "Deploy key"
        key.id = 2
        repo.get_keys.return_value = [key]

        result = run_deploy_keys_checks(org, MagicMock())
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Audit Log Tests (1)
# ---------------------------------------------------------------------------

class TestAuditLogChecks:
    def test_audit_log_accessible(self):
        from checks.audit_log import run_audit_log_checks
        org = _mock_org()
        audit_iter = MagicMock()
        audit_iter.__getitem__ = MagicMock(return_value=[MagicMock(), MagicMock()])
        org.get_audit_log.return_value = audit_iter

        result = run_audit_log_checks(org, MagicMock())
        assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# Webhooks Tests (2)
# ---------------------------------------------------------------------------

class TestWebhooksChecks:
    def test_secure_webhook(self):
        from checks.webhooks import run_webhooks_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        hook = MagicMock()
        hook.id = 1
        hook.config = {"url": "https://example.com/hook", "secret": "s3cr3t"}
        repo.get_hooks.return_value = [hook]

        result = run_webhooks_checks(org, MagicMock())
        assert result["status"] == "pass"

    def test_insecure_webhook(self):
        from checks.webhooks import run_webhooks_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        hook = MagicMock()
        hook.id = 2
        hook.config = {"url": "http://example.com/hook"}
        repo.get_hooks.return_value = [hook]

        result = run_webhooks_checks(org, MagicMock())
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# CODEOWNERS Tests (1)
# ---------------------------------------------------------------------------

class TestCodeownersChecks:
    def test_codeowners_present(self):
        from checks.codeowners import run_codeowners_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]
        repo.get_contents.return_value = MagicMock()  # CODEOWNERS found

        result = run_codeowners_checks(org, MagicMock())
        assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# CI/CD Tests (1)
# ---------------------------------------------------------------------------

class TestCICDChecks:
    def test_workflows_found(self):
        from checks.ci_cd import run_ci_cd_checks
        org = _mock_org()
        repo = _mock_repo()
        org.get_repos.return_value = [repo]

        wf_file = MagicMock()
        wf_file.name = "ci.yml"
        wf_file.decoded_content = b"name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest"
        repo.get_contents.return_value = [wf_file]

        result = run_ci_cd_checks(org, MagicMock())
        assert result["check"] == "ci_cd"
        assert result["total"] >= 1


# ---------------------------------------------------------------------------
# Orchestrator Tests (1)
# ---------------------------------------------------------------------------

class TestOrchestrator:
    def test_all_checks_registered(self):
        from checks import ALL_CHECKS
        expected = {
            "branch_protection", "secret_scanning", "dependabot", "two_factor",
            "deploy_keys", "audit_log", "webhooks", "codeowners", "ci_cd",
        }
        assert set(ALL_CHECKS.keys()) == expected
        assert len(ALL_CHECKS) == 9
