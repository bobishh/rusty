from pathlib import Path
import unittest


class DeployWorkflowTests(unittest.TestCase):
    def test_rusty_owns_immutable_deploy_and_rollback_workflow(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/deploy-rusty.yml").read_text()
        self.assertIn("rusty-release-${{ steps.source.outputs.sha }}-${{ steps.source.outputs.attempt }}", workflow)
        self.assertIn("python3 scripts/verify_release.py .release/rusty", workflow)
        self.assertIn("node scripts/deploy_release.mjs", workflow)
        self.assertLess(workflow.index("python3 scripts/verify_release.py"), workflow.index("node scripts/deploy_release.mjs"))
        self.assertIn("environment: production", workflow)
        self.assertIn("RUSTY_DEPLOY_SPEC", workflow)
        self.assertIn("RUSTY_DEPLOY_SSH_KEY", workflow)
        self.assertIn("packages: write", workflow)
        self.assertNotIn("Confirm live Rusty executable", workflow)
        self.assertNotIn("bobishh/tincanban", workflow)
        self.assertNotIn("RUSTY_REVISION", workflow)
        self.assertNotIn("SDK_SHA", workflow)


if __name__ == "__main__":
    unittest.main()
