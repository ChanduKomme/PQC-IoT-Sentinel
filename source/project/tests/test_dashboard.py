"""API smoke tests with no Splunk credentials or external requests."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'dashboard/backend'))

class DashboardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SPLUNK_PASS'] = ''
        from fastapi.testclient import TestClient
        from app import app
        cls.client = TestClient(app)

    def test_offline_endpoints(self):
        for path in ['/api/health', '/api/splunk/status', '/api/events/recent',
                     '/api/events/counts', '/api/events/timeline', '/api/devices',
                     '/api/attacks/summary', '/api/governance/summary',
                     '/api/governance/risks', '/api/overview']:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.text)
        data = self.client.get('/api/overview').json()
        self.assertFalse(data['splunk']['ok'])
        self.assertFalse(data['ok'])
        self.assertGreater(len(data['governance']['risks']), 0)

    def test_built_frontend(self):
        if not (ROOT/'dashboard/frontend/dist/index.html').exists():
            self.skipTest('run npm ci && npm run build first')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers['content-type'])

    def test_cors_and_validation(self):
        response = self.client.get('/api/health', headers={'Origin': 'https://untrusted.example'})
        self.assertNotIn('access-control-allow-origin', response.headers)
        self.assertEqual(self.client.get('/api/events/recent?limit=501').status_code, 422)

if __name__ == '__main__':
    unittest.main()
