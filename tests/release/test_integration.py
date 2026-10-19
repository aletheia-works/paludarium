"""Upload adapter tests only; these never claim registry/OIDC success."""
import unittest
from test_policy import valid
import check

class ReleaseIntegrationTests(unittest.TestCase):
    def test_all_success_mock_adapter(self):
        state,inventory=valid();uploaded=[]
        def upload(n,v):uploaded.append(n);return dict(published=True)
        result=check.publish_sequence(state,inventory,upload,lambda n,r:True)
        self.assertEqual(len(result),12);self.assertEqual(result,uploaded)
    def test_preflight_denies_upload_zero(self):
        state,inventory=valid();state['environment']={};uploaded=[]
        with self.assertRaises(ValueError):check.publish_sequence(state,inventory,lambda n,v:uploaded.append(n),lambda n,r:True)
        self.assertEqual(uploaded,[])
    def test_middle_crate_failure_stops_later(self):
        state,inventory=valid();uploaded=[]
        def upload(n,v):uploaded.append(n);return dict(published=len(uploaded)<3)
        with self.assertRaises(ValueError):check.publish_sequence(state,inventory,upload,lambda n,r:True)
        self.assertEqual(len(uploaded),3);self.assertNotIn('@aletheia-works/paludarium-wasm',uploaded)
    def test_post_publication_digest_failure(self):
        state,inventory=valid();uploaded=[]
        def upload(n,v):uploaded.append(n);return dict(published=True)
        with self.assertRaises(ValueError):check.publish_sequence(state,inventory,upload,lambda n,r:False)
        self.assertEqual(len(uploaded),1)

if __name__=='__main__':unittest.main()
