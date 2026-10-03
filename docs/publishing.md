# Publishing watchpost-cli

The project is Watchpost. The distribution name is `watchpost-cli`.
The command and import module remain `watchpost`.
The `watchpost` package on PyPI and TestPyPI belongs to an unrelated project.
Do not install both distributions into the same Python environment.

## One-time PyPI account setup

Use your existing accounts. Keep email verification and two-factor authentication enabled.
Do not create or share an API token for this workflow.

Open the account-level Publishing page on each service:

- [TestPyPI pending publishers](https://test.pypi.org/manage/account/publishing/)
- [PyPI pending publishers](https://pypi.org/manage/account/publishing/)

Choose **Add a new pending publisher**, then **GitHub**.

| Field | TestPyPI | PyPI |
|---|---|---|
| PyPI project name | `watchpost-cli` | `watchpost-cli` |
| Owner | `ejames-dev` | `ejames-dev` |
| Repository name | `watchpost` | `watchpost` |
| Workflow name | `publish.yml` | `publish.yml` |
| Environment name | `testpypi` | `pypi` |

Enter only the filename `publish.yml`, not `.github/workflows/publish.yml`.
Click **Add** on each site. The configurations are separate and do not transfer between services.

A pending publisher does not reserve the name or create the project.
The first successful upload creates the project and converts the publisher to a normal trusted publisher.
If the site rejects the name, stop and investigate before changing package metadata again.

Source: [PyPI's pending-publisher documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## GitHub environment setup

In this repository's **Settings → Environments**, configure:

| Setting | `testpypi` | `pypi` |
|---|---|---|
| Required reviewer | `ejames-dev` | `ejames-dev` |
| Prevent self-review | Off, for this single-maintainer repository | Off, for this single-maintainer repository |
| Administrator bypass | Disabled | Disabled |
| Allowed deployment ref | Branch `main` | Tags matching `v*` |

Do not remove the approval requirement to work around a publishing error.
The publishing job alone gets `id-token: write` for OIDC. The build job has no publishing identity permission.
No stored PyPI password or API token is used.

## Workflow behavior

`.github/workflows/publish.yml` runs only through **Actions → Publish Python package → Run workflow**.
Creating a tag or GitHub Release does not trigger it.

- **TestPyPI:** choose branch `main` and registry `testpypi`.
- **PyPI:** choose the existing release tag, such as `v0.1.0`, and registry `pypi`.

The workflow rejects unexpected package names and refs before installing project dependencies.
A PyPI tag must match the package version exactly and point to a commit reachable from `main`.
It runs tests and lint, builds once, checks metadata, smoke-tests the wheel, and stores a checksummed bundle.
After environment approval, the publisher uploads that exact bundle without rebuilding it.
Separate TestPyPI and PyPI runs build separate bundles. Do not assume their archive bytes are identical.

Uploads to TestPyPI are real uploads, not dry runs. Registry versions cannot simply be overwritten.
The workflow deliberately fails on existing files instead of skipping them.

## First publication sequence

1. Merge the package-name and workflow changes after CI passes.
2. Confirm both pending publishers and GitHub environments match the settings above.
3. Obtain explicit approval for the TestPyPI upload.
4. Run the TestPyPI workflow from the approved `main` commit.
5. Approve its `testpypi` environment and verify the uploaded package.
6. Confirm the release notes and approve the final release commit.
7. Create and verify the signed release tag and publish the approved GitHub Release.
8. Obtain separate approval for the production PyPI upload.
9. Run the PyPI workflow at that tag and approve its `pypi` environment.
10. Verify the registry files, installed metadata, and CLI behavior.

Do not mark a release as published based only on an Actions job starting or a version field changing.
Confirm the public registry result after a successful upload.

## Verify a TestPyPI installation

After version `0.1.0` exists on TestPyPI, use a new virtual environment outside the repository.
If the path below already exists, choose a fresh environment path before running these commands:

```bash
python3 -m venv /tmp/watchpost-testpypi-check
/tmp/watchpost-testpypi-check/bin/python -m pip install \
  --index-url https://pypi.org/simple/ 'defusedxml==0.7.1'
/tmp/watchpost-testpypi-check/bin/python -m pip install \
  --no-deps --index-url https://test.pypi.org/simple/ 'watchpost-cli==0.1.0'
/tmp/watchpost-testpypi-check/bin/python -m pip check
/tmp/watchpost-testpypi-check/bin/python -I -c \
  'from importlib.metadata import version; print(version("watchpost-cli"))'
/tmp/watchpost-testpypi-check/bin/watchpost --help
```

Install dependencies from production PyPI, then install only this package from TestPyPI with `--no-deps`.
Do not mix the two indexes with `--extra-index-url`.
Run the synthetic comparison with known local example files before approving production publication.

For production, use `watchpost-cli`, not `watchpost`, in the install command.
Keep registry credentials, account recovery codes, and two-factor codes out of issues and chat.
