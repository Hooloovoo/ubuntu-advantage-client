from uaclient import apt, snap
from uaclient.api.api import APIEndpoint
from uaclient.api.data_types import AdditionalInfo
from uaclient.config import UAConfig
from uaclient.data_types import DataObject, Field, StringDataValue


class InstalledPackagesResults(DataObject, AdditionalInfo):
    fields = [
        Field("manifest_data", StringDataValue),
    ]

    def __init__(self, manifest_data: str):
        self.manifest_data = manifest_data


def get_installed_packages() -> InstalledPackagesResults:
    return _get_installed_packages(UAConfig())


def _get_installed_packages(cfg: UAConfig) -> InstalledPackagesResults:
    """Returns the status of installed packages (apt and snap packages)
    Returns a string in manifest format i.e. package_name\tversion
    """
    manifest = ""
    apt_pkgs = apt.get_installed_packages(include_versions=True)
    for apt_pkg in apt_pkgs:
        manifest += apt_pkg + "\n"

    pkgs = snap.get_installed_packages()
    for pkg in pkgs:
        manifest += "{app}\t{version}\n".format(
            app=pkg.name, version=pkg.version
        )

    return InstalledPackagesResults(manifest_data=manifest)


endpoint = APIEndpoint(
    version="v1",
    name="Packages",
    fn=_get_installed_packages,
    options_cls=None,
)
