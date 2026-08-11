from app.config import Development, DevNL, ProdNL, TestNL, configs


def test_configs_maps_every_nl_deploy_environment():
    # notifynl-charts-private sets NOTIFY_ENVIRONMENT to one of these values
    # for every app in the fork (see templates/configmaps.yaml) -- a missing
    # key here silently falls back to the bare upstream Config (real-AWS SQS
    # defaults, no NL overrides) instead of raising, so this only guards
    # against a regression, not a startup crash. pytest.ini sets
    # NOTIFY_ENVIRONMENT=test locally (not testnl), so "test" must keep
    # resolving to TestNL too -- see tests/celery/test_nl_tasks.py and
    # tests/celery/test_tasks.py, which depend on the NL-specific
    # ANTIVIRUS_*/bucket config TestNL provides.
    assert configs["development"] is DevNL
    assert configs["test"] is TestNL
    assert configs["testnl"] is TestNL
    assert configs["production"] is ProdNL


def test_configs_does_not_shadow_upstream_development():
    assert configs["development"] is not Development
