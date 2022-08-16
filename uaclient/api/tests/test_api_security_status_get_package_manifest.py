import mock

from uaclient.api.u.security.package_manifest.v1 import _get_installed_packages

M_PATH = "uaclient.api.u.security.package_manifest.v1"


@mock.patch("uaclient.snap.system.subp")
@mock.patch(M_PATH + ".apt.get_installed_packages")
class TestPackageInstalledV1:
    def test_snap_packages_added(self, apt_cache, sys_subp, FakeConfig):
        apt_cache.return_value = []
        sys_subp.return_value = (
            "Name  Version Rev Tracking Publisher Notes\n"
            "helloworld 6.0.16 126 latest/stable dev1 -\n"
            "bare 1.0 5 latest/stable canonical** base\n"
            "canonical-livepatch 10.2.3 146 latest/stable canonical** -\n"
        ), ""
        result = _get_installed_packages(FakeConfig())
        assert (
            "helloworld\t6.0.16\nbare\t1.0\ncanonical-livepatch\t10.2.3\n"
            == result.manifest_data
        )

    def test_apt_packages_added(
        self, installed_apt_pkgs, sys_subp, FakeConfig
    ):
        sys_subp.return_value = "", ""
        apt_pkgs = ["one\t4:1.0.2", "two\t0.1.1"]
        installed_apt_pkgs.return_value = apt_pkgs
        result = _get_installed_packages(FakeConfig())
        assert "one\t4:1.0.2\ntwo\t0.1.1\n" == result.manifest_data

    def test_apt_snap_packages_added(
        self, installed_apt_pkgs, sys_subp, FakeConfig
    ):
        apt_pkgs = ["one\t4:1.0.2", "two\t0.1.1"]
        sys_subp.return_value = (
            "Name  Version Rev Tracking Publisher Notes\n"
            "helloworld 6.0.16 126 latest/stable dev1 -\n"
            "bare 1.0 5 latest/stable canonical** base\n"
            "canonical-livepatch 10.2.3 146 latest/stable canonical** -\n"
        ), ""
        installed_apt_pkgs.return_value = apt_pkgs
        result = _get_installed_packages(FakeConfig())
        assert (
            "one\t4:1.0.2\ntwo\t0.1.1\n"
            + "helloworld\t6.0.16\nbare\t1.0\n"
            + "canonical-livepatch\t10.2.3\n"
            == result.manifest_data
        )
