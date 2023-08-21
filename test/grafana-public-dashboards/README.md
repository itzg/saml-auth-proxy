
## Setup

Create the proxy's cert and key files [like in the README](../../README.md#trying-it-out)

Bring up the services setting the `BASE_URL` to the publicly resolvable URL of your service:

```shell
BASE_URL=... docker compose up -d --build
```

Export and upload the IDP metadata [like in the README](../../README.md#trying-it-out)

Access Grafana via the proxy at <http://localhost:8080>

Login as Rick via `samltest.idp`  since the test configures that user as admin.

Go to the pre-provisioned dashboard at the path `/d/c6f2205a-a683-417f-b177-b916085d5519/public?orgId=1`, [make it public](https://grafana.com/docs/grafana/latest/dashboards/dashboard-public/#make-a-dashboard-public), and copy the public dashboard link.

Open an incognito tab (or equivalent) and confirm access to the public dashboard without login. Go to some other path like `/` and confirm that you are redirected to login via SAML auth.