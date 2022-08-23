from collections import defaultdict
from enum import Enum
from random import choice
from typing import Any, DefaultDict, Dict, List, Tuple  # noqa: F401

from apt import Cache  # type: ignore
from apt import package as apt_package

from uaclient import messages
from uaclient.config import UAConfig
from uaclient.entitlements import ESMAppsEntitlement, ESMInfraEntitlement
from uaclient.entitlements.entitlement_status import (
    ApplicabilityStatus,
    ApplicationStatus,
)
from uaclient.status import status
from uaclient.system import (
    get_eol_date_for_series,
    get_platform_info,
    is_current_series_lts,
    is_supported,
)

series = get_platform_info()["series"]

ESM_SERVICES = ("esm-infra", "esm-apps")


ORIGIN_INFORMATION_TO_SERVICE = {
    ("Ubuntu", "{}-security".format(series)): "standard-security",
    ("UbuntuESMApps", "{}-apps-security".format(series)): "esm-apps",
    ("UbuntuESM", "{}-infra-security".format(series)): "esm-infra",
    ("UbuntuESMApps", "{}-apps-updates".format(series)): "esm-apps",
    ("UbuntuESM", "{}-infra-updates".format(series)): "esm-infra",
}


class UpdateStatus(Enum):
    "Represents the availability of a security package."
    AVAILABLE = "upgrade_available"
    UNATTACHED = "pending_attach"
    NOT_ENABLED = "pending_enable"
    UNAVAILABLE = "upgrade_unavailable"


def get_installed_packages_by_origin() -> DefaultDict[
    "str", List[apt_package.Package]
]:
    result = defaultdict(list)

    cache = Cache()
    installed_packages = [package for package in cache if package.is_installed]
    result["all"] = installed_packages

    for package in installed_packages:
        result[get_origin_for_package(package)].append(package)

    return result


def get_origin_for_package(package: apt_package.Package) -> str:
    """
    Returns the origin for a package installed in the system.

    Technically speaking, packages don't have origins - their versions do.
    We check the available versions (installed, candidate) to determine the
    most reasonable origin for the package.
    """
    available_origins = package.installed.origins

    # If the installed version for a package has a single origin, it means that
    # only the local dpkg reference is there. Then, we check if there is a
    # candidate version. No candidate means we don't know anything about the
    # package. Otherwise we check for the origins of the candidate version.
    if len(available_origins) == 1:
        if package.installed == package.candidate:
            return "unknown"
        available_origins = package.candidate.origins

    for origin in available_origins:
        service = ORIGIN_INFORMATION_TO_SERVICE.get(
            (origin.origin, origin.archive), ""
        )
        if service in ESM_SERVICES:
            return service
        if origin.origin == "Ubuntu":
            return origin.component

    return "third-party"


def get_update_status(service_name: str, ua_info: Dict[str, Any]) -> str:
    """Defines the update status for a package based on the service name.

    For ESM-[Infra|Apps] packages, first checks if Pro is attached. If this is
    the case, also check for availability of the service.
    """
    if service_name == "standard-security" or (
        ua_info["attached"] and service_name in ua_info["enabled_services"]
    ):
        return UpdateStatus.AVAILABLE.value
    if not ua_info["attached"]:
        return UpdateStatus.UNATTACHED.value
    if service_name in ua_info["entitled_services"]:
        return UpdateStatus.NOT_ENABLED.value
    return UpdateStatus.UNAVAILABLE.value


def filter_security_updates(
    packages: List[apt_package.Package],
) -> DefaultDict[str, List[Tuple[apt_package.Version, str]]]:
    """Filters a list of packages looking for available security updates.

    Checks if the package has a greater version available, and if the origin of
    this version matches any of the series' security repositories.
    """
    result = defaultdict(list)

    for package in packages:
        for version in package.versions:
            if version > package.installed:
                for origin in version.origins:
                    service = ORIGIN_INFORMATION_TO_SERVICE.get(
                        (origin.origin, origin.archive)
                    )
                    if service:
                        result[service].append((version, origin.site))
                        break  # No need to loop through all the origins

    return result


def get_ua_info(cfg: UAConfig) -> Dict[str, Any]:
    """Returns the Pro information based on the config object."""
    ua_info = {
        "attached": False,
        "enabled_services": [],
        "entitled_services": [],
    }  # type: Dict[str, Any]

    status_dict = status(cfg=cfg, show_all=True)
    if status_dict["attached"]:
        ua_info["attached"] = True
        for service in status_dict["services"]:
            if service["name"] in ESM_SERVICES:
                if service["entitled"] == "yes":
                    ua_info["entitled_services"].append(service["name"])
                if service["status"] == "enabled":
                    ua_info["enabled_services"].append(service["name"])

    return ua_info


def security_status_dict(cfg: UAConfig) -> Dict[str, Any]:
    """Returns the status of security updates on a system.

    The returned dict has a 'packages' key with a list of all installed
    packages which can receive security updates, with or without ESM,
    reflecting the availability of the update based on the Pro status.

    There is also a summary with the Ubuntu Pro information and the package
    counts.
    """
    ua_info = get_ua_info(cfg)

    summary = {"ua": ua_info}  # type: Dict[str, Any]
    packages = []
    packages_by_origin = get_installed_packages_by_origin()

    installed_packages = packages_by_origin["all"]
    summary["num_installed_packages"] = len(installed_packages)

    security_upgradable_versions = filter_security_updates(installed_packages)

    for service, version_list in security_upgradable_versions.items():
        status = get_update_status(service, ua_info)
        for version, origin in version_list:
            packages.append(
                {
                    "package": version.package.name,
                    "version": version.version,
                    "service_name": service,
                    "status": status,
                    "origin": origin,
                    "download_size": version.size,
                }
            )

    summary["num_main_packages"] = len(packages_by_origin["main"])
    summary["num_restricted_packages"] = len(packages_by_origin["restricted"])
    summary["num_universe_packages"] = len(packages_by_origin["universe"])
    summary["num_multiverse_packages"] = len(packages_by_origin["multiverse"])
    summary["num_third_party_packages"] = len(
        packages_by_origin["third-party"]
    )
    summary["num_unknown_packages"] = len(packages_by_origin["unknown"])
    summary["num_esm_infra_packages"] = len(packages_by_origin["esm-infra"])
    summary["num_esm_apps_packages"] = len(packages_by_origin["esm-apps"])

    summary["num_esm_infra_updates"] = len(
        security_upgradable_versions["esm-infra"]
    )
    summary["num_esm_apps_updates"] = len(
        security_upgradable_versions["esm-apps"]
    )
    summary["num_standard_security_updates"] = len(
        security_upgradable_versions["standard-security"]
    )

    return {"_schema_version": "0.1", "summary": summary, "packages": packages}


def _print_package_summary(
    package_lists: DefaultDict[str, List[apt_package.Package]],
    show_items: str = "all",
    always_show: bool = False,
) -> None:
    total_packages = len(package_lists["all"])
    print(messages.SS_SUMMARY_TOTAL.format(count=total_packages))

    offset = " " * (len(str(total_packages)) + 1)

    if show_items in ("all", "esm-infra"):
        packages_mr = (
            len(package_lists["main"])
            + len(package_lists["restricted"])
            + len(package_lists["esm-infra"])
        )
        print(
            messages.SS_SUMMARY_ARCHIVE.format(
                offset=offset,
                count=packages_mr,
                plural="s",
                repository="Main/Restricted",
            )
        )

    if show_items in ("all", "esm-apps"):
        packages_um = (
            len(package_lists["universe"])
            + len(package_lists["multiverse"])
            + len(package_lists["esm-apps"])
        )
        if packages_um or always_show:
            print(
                messages.SS_SUMMARY_ARCHIVE.format(
                    offset=offset,
                    count=packages_um,
                    plural="s" if packages_um > 1 else "",
                    repository="Universe/Multiverse",
                )
            )

    if show_items in ("all", "third-party"):
        packages_thirdparty = len(package_lists["third-party"])
        if packages_thirdparty or always_show:
            msg = messages.SS_SUMMARY_THIRD_PARTY_SN
            if packages_thirdparty > 1:
                msg = messages.SS_SUMMARY_THIRD_PARTY_PL
            print(msg.format(offset=offset, count=packages_thirdparty))

    if show_items in ("all", "unknown"):
        packages_unknown = len(package_lists["unknown"])
        if packages_unknown or always_show:
            print(
                messages.SS_SUMMARY_UNAVAILABLE.format(
                    offset=offset,
                    count=packages_unknown,
                    plural="s" if packages_unknown > 1 else "",
                )
            )

    print("")


def _print_service_support(
    service: str,
    repository: str,
    service_status: ApplicationStatus,
    service_applicability: ApplicabilityStatus,
    installed_updates: int,
    available_updates: int,
    is_attached: bool,
):
    eol_date_esm = get_eol_date_for_series(series, "eol-esm")
    if service_status == ApplicationStatus.ENABLED:
        print(
            messages.SS_SERVICE_ENABLED.format(
                repository=repository,
                service=service,
                year=eol_date_esm["year"],
                updates=installed_updates if installed_updates else "no",
                plural="" if installed_updates == 1 else "s",
            )
        )
    else:
        print(
            messages.SS_SERVICE_ADVERTISE.format(
                service=service,
                repository=repository,
                year=eol_date_esm["year"],
                updates=available_updates,
                plural="s" if available_updates > 1 else "",
            )
        )
        if (
            is_attached
            and service_applicability == ApplicabilityStatus.APPLICABLE
        ):
            print(messages.SS_SERVICE_COMMAND.format(service=service))


def security_status(cfg: UAConfig):
    esm_infra_status = ESMInfraEntitlement(cfg).application_status()[0]
    esm_infra_applicability = ESMInfraEntitlement(cfg).applicability_status()[
        0
    ]
    esm_apps_status = ESMAppsEntitlement(cfg).application_status()[0]
    esm_apps_applicability = ESMAppsEntitlement(cfg).applicability_status()[0]

    is_lts = is_current_series_lts()
    is_attached = get_ua_info(cfg)["attached"]

    packages_by_origin = get_installed_packages_by_origin()
    security_upgradable_versions = filter_security_updates(
        packages_by_origin["all"]
    )

    _print_package_summary(packages_by_origin)

    print(messages.SS_HELP_CALL)
    print("")

    if is_lts and not is_attached:
        print(messages.SS_UNATTACHED)
        print("")

    if is_supported(series):
        eol_date = get_eol_date_for_series(series)
        lts = " with LTS"
        date = eol_date["year"]
        if not is_lts:
            lts = ""
            date = "{}/{}".format(eol_date["month"], eol_date["year"])
        print(messages.SS_SUPPORT.format(lts=lts, date=date))
        print("")
    elif is_lts:
        _print_service_support(
            service="esm-infra",
            repository="Main/Restricted",
            service_status=esm_infra_status,
            service_applicability=esm_infra_applicability,
            installed_updates=len(packages_by_origin["esm-infra"]),
            available_updates=len(security_upgradable_versions["esm-infra"]),
            is_attached=is_attached,
        )
        print("")

    if is_lts:
        _print_service_support(
            service="esm-apps",
            repository="Universe/Multiverse",
            service_status=esm_apps_status,
            service_applicability=esm_apps_applicability,
            installed_updates=len(packages_by_origin["esm-apps"]),
            available_updates=len(security_upgradable_versions["esm-apps"]),
            is_attached=is_attached,
        )
        print("")

    if is_lts and not is_attached:
        print(messages.SS_LEARN_MORE)


def list_third_party_packages():
    packages_by_origin = get_installed_packages_by_origin()
    third_party_packages = packages_by_origin["third-party"]

    _print_package_summary(packages_by_origin, show_items="third-party")

    if third_party_packages:
        print(messages.SS_THIRD_PARTY)

        print("")
        print("Packages:")
        for package in third_party_packages:
            print(package.name, end=" ")

        print("")
        print("")
        print(
            messages.SS_POLICY_HINT.format(
                package=choice(third_party_packages).name
            )
        )
    else:
        print(messages.SS_NO_THIRD_PARTY)


def list_unavailable_packages():
    packages_by_origin = get_installed_packages_by_origin()
    unknown_packages = packages_by_origin["unknown"]

    _print_package_summary(packages_by_origin, show_items="unknown")

    if unknown_packages:
        print(messages.SS_UNAVAILABLE)

        print("")
        print("Packages:")
        for package in unknown_packages:
            print(package.name, end=" ")

        print("")
        print("")
        print(
            messages.SS_POLICY_HINT.format(
                package=choice(unknown_packages).name
            )
        )
    else:
        print(messages.SS_NO_UNAVAILABLE)


def list_esm_infra_packages(cfg):
    packages_by_origin = get_installed_packages_by_origin()
    infra_packages = packages_by_origin["esm-infra"]
    mr_packages = packages_by_origin["main"] + packages_by_origin["restricted"]

    all_infra_packages = infra_packages + mr_packages

    infra_updates = set()
    security_upgradable_versions = filter_security_updates(all_infra_packages)[
        "esm-infra"
    ]
    for update, _ in security_upgradable_versions:
        infra_updates.add(update.package)

    is_lts = is_current_series_lts()

    esm_infra_status = ESMInfraEntitlement(cfg).application_status()[0]
    esm_infra_applicability = ESMInfraEntitlement(cfg).applicability_status()[
        0
    ]

    _print_package_summary(
        packages_by_origin, show_items="esm-infra", always_show=True
    )

    if is_supported(series):
        eol_date = get_eol_date_for_series(series)
        lts = " with LTS"
        date = eol_date["year"]
        if not is_lts:
            lts = ""
            date = "{}/{}".format(eol_date["month"], eol_date["year"])
        print(messages.SS_SUPPORT.format(lts=lts, date=date))
        print("")
    elif is_lts:
        _print_service_support(
            service="esm-infra",
            repository="Main/Restricted",
            service_status=esm_infra_status,
            service_applicability=esm_infra_applicability,
            installed_updates=len(infra_packages),
            available_updates=len(infra_updates),
            is_attached=False,  # don't care about the `enable` message
        )
        print("")
        print(messages.SS_SERVICE_HELP.format(service="esm-infra"))
        print("")

    if not is_lts:
        print(messages.SS_NO_PRO_SUPPORT)
        return

    print(messages.SS_BOLD_PACKAGES.format(service="esm-infra"))
    print("Packages:")
    for package in all_infra_packages:
        if package in infra_updates:
            print(
                "{bold}{package_name}{end_bold}".format(
                    bold=messages.TxtColor.BOLD,
                    package_name=package.name,
                    end_bold=messages.TxtColor.ENDC,
                ),
                end=" ",
            )
        else:
            print(package.name, end=" ")
    print("")
    print("")
    print(
        messages.SS_POLICY_HINT.format(package=choice(all_infra_packages).name)
    )


def list_esm_apps_packages(cfg):
    packages_by_origin = get_installed_packages_by_origin()
    apps_packages = packages_by_origin["esm-apps"]
    um_packages = (
        packages_by_origin["universe"] + packages_by_origin["multiverse"]
    )

    all_apps_packages = apps_packages + um_packages

    apps_updates = set()
    security_upgradable_versions = filter_security_updates(all_apps_packages)[
        "esm-apps"
    ]
    for update, _ in security_upgradable_versions:
        apps_updates.add(update.package)

    is_lts = is_current_series_lts()

    esm_apps_status = ESMAppsEntitlement(cfg).application_status()[0]
    esm_apps_applicability = ESMAppsEntitlement(cfg).applicability_status()[0]

    _print_package_summary(
        packages_by_origin, show_items="esm-apps", always_show=True
    )

    if not is_lts:
        print(messages.SS_NO_PRO_SUPPORT)
        return

    _print_service_support(
        service="esm-apps",
        repository="Universe/Multiverse",
        service_status=esm_apps_status,
        service_applicability=esm_apps_applicability,
        installed_updates=len(apps_packages),
        available_updates=len(apps_updates),
        is_attached=False,  # don't care about the `enable` message
    )
    print("")
    print(messages.SS_SERVICE_HELP.format(service="esm-apps"))
    print("")

    if all_apps_packages:
        print(messages.SS_BOLD_PACKAGES.format(service="esm-apps"))
        print("Packages:")
        for package in all_apps_packages:
            if package in apps_updates:
                print(
                    "{bold}{package_name}{end_bold}".format(
                        bold=messages.TxtColor.BOLD,
                        package_name=package.name,
                        end_bold=messages.TxtColor.ENDC,
                    ),
                    end=" ",
                )
            else:
                print(package.name, end=" ")

        print("")
        print("")
        print(
            messages.SS_POLICY_HINT.format(
                package=choice(all_apps_packages).name
            )
        )
