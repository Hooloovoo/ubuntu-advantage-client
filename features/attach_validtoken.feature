@uses.config.contract_token
Feature: Command behaviour when attaching a machine to an Ubuntu Pro
        subscription using a valid token

    @series.kinetic
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attached command in a non-lts ubuntu machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        And I run `pro status --all` as non-root
        Then stdout matches regexp:
            """
            SERVICE       +ENTITLED  STATUS    DESCRIPTION
            cc-eal        +yes      +n/a      +Common Criteria EAL2 Provisioning Packages
            cis           +yes      +n/a      +Security compliance and audit tools
            esm-apps      +yes      +n/a      +Expanded Security Maintenance for Applications
            esm-infra     +yes      +n/a      +Expanded Security Maintenance for Infrastructure
            fips          +yes      +n/a      +NIST-certified core packages
            fips-updates  +yes      +n/a      +NIST-certified core packages with priority security updates
            livepatch     +yes      +n/a      +Canonical Livepatch service
            """

        Examples: ubuntu release
            | release |
            | kinetic |

    @series.lts
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attach command in a ubuntu lxd container
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I run `apt-get update` with sudo, retrying exit [100]
        And I run `apt install update-motd` with sudo, retrying exit [100]
        And I run `DEBIAN_FRONTEND=noninteractive apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y <downrev_pkg>` with sudo, retrying exit [100]
        And I run `pro refresh messages` with sudo
        Then stdout matches regexp:
        """
        Successfully updated Ubuntu Pro related APT and MOTD messages.
        """
        When I run `update-motd` with sudo
        Then if `<release>` in `xenial` and stdout matches regexp:
        """
        \d+ update(s)? can be applied immediately.
        \d+ of these updates (is a|are) standard security update(s)?.
        """
        Then if `<release>` in `bionic` and stdout matches regexp:
        """
        \d+ update(s)? can be applied immediately.
        \d+ of these updates (is a|are) standard security update(s)?.
        """
        Then if `<release>` in `focal` and stdout matches regexp:
        """
        \d+ update(s)? can be applied immediately.
        """
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        Ubuntu Pro: ESM Infra enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        esm-apps     +yes      +enabled  +Expanded Security Maintenance for Applications
        esm-infra    +yes      +enabled  +Expanded Security Maintenance for Infrastructure
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """
        When I verify that running `pro attach contract_token` `with sudo` exits `2`
        Then stderr matches regexp:
        """
        This machine is already attached to '.+'
        To use a different subscription first run: sudo pro detach.
        """

        Examples: ubuntu release packages
           | release | downrev_pkg                 | cc_status | cis_or_usg | cis      | fips     | livepatch_desc                |
           | xenial  | libkrad0=1.13.2+dfsg-5      | disabled  | cis        | disabled | disabled | Canonical Livepatch service   |
           | bionic  | libkrad0=1.16-2build1       | disabled  | cis        | disabled | disabled | Canonical Livepatch service   |
           | focal   | hello=2.10-2ubuntu2         | n/a       | usg        | disabled | disabled | Canonical Livepatch service   |
           | jammy   | hello=2.10-2ubuntu4         | n/a       | usg        | n/a      | n/a      | Canonical Livepatch service   |

    @series.lts
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attach command with attach config
        Given a `<release>` machine with ubuntu-advantage-tools installed
        # simplest happy path
        When I create the file `/tmp/attach.yaml` with the following
        """
        token: <contract_token>
        """
        When I replace `<contract_token>` in `/tmp/attach.yaml` with token `contract_token`
        When I run `pro attach --attach-config /tmp/attach.yaml` with sudo
        Then stdout matches regexp:
        """
        esm-apps +yes +enabled
        """
        And stdout matches regexp:
        """
        esm-infra +yes +enabled
        """
        And stdout matches regexp:
        """
        <cis_or_usg> +yes +disabled
        """
        When I run `pro detach --assume-yes` with sudo
        # don't allow both token on cli and config
        Then I verify that running `pro attach TOKEN --attach-config /tmp/attach.yaml` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        Do not pass the TOKEN arg if you are using --attach-config.
        Include the token in the attach-config file instead.
        """
        # happy path with service overrides
        When I create the file `/tmp/attach.yaml` with the following
        """
        token: <contract_token>
        enable_services:
          - esm-apps
          - <cis_or_usg>
        """
        When I replace `<contract_token>` in `/tmp/attach.yaml` with token `contract_token`
        When I run `pro attach --attach-config /tmp/attach.yaml` with sudo
        Then stdout matches regexp:
        """
        esm-apps +yes +enabled
        """
        And stdout matches regexp:
        """
        esm-infra +yes +disabled
        """
        And stdout matches regexp:
        """
        <cis_or_usg> +yes +enabled
        """
        When I run `pro detach --assume-yes` with sudo
        # missing token
        When I create the file `/tmp/attach.yaml` with the following
        """
        enable_services:
          - esm-apps
          - <cis_or_usg>
        """
        Then I verify that running `pro attach --attach-config /tmp/attach.yaml` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        Error while reading /tmp/attach.yaml: Got value with incorrect type for field
        "token": Expected value with type StringDataValue but got type: null
        """
        # other schema error
        When I create the file `/tmp/attach.yaml` with the following
        """
        token: <contract_token>
        enable_services: {cis: true}
        """
        When I replace `<contract_token>` in `/tmp/attach.yaml` with token `contract_token`
        Then I verify that running `pro attach --attach-config /tmp/attach.yaml` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        Error while reading /tmp/attach.yaml: Got value with incorrect type for field
        "enable_services": Expected value with type list but got type: dict
        """
        # invalid service name
        When I create the file `/tmp/attach.yaml` with the following
        """
        token: <contract_token>
        enable_services:
          - esm-apps
          - nonexistent
          - nonexistent2
        """
        When I replace `<contract_token>` in `/tmp/attach.yaml` with token `contract_token`
        Then I verify that running `pro attach --attach-config /tmp/attach.yaml` `with sudo` exits `1`
        Then stdout matches regexp:
        """
        esm-apps +yes +enabled
        """
        And stdout matches regexp:
        """
        esm-infra +yes +disabled
        """
        Then stderr matches regexp:
        """
        Cannot enable unknown service 'nonexistent, nonexistent2'.
        """
        Examples: ubuntu
           | release | cis_or_usg |
           | xenial  | cis        |
           | bionic  | cis        |
           | focal   | usg        |

    @series.all
    @uses.config.machine_type.aws.generic
    Scenario Outline: Attach command in an generic AWS Ubuntu VM
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I create the file `/tmp/machine-token-overlay.json` with the following:
        """
        {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {
                            "type": "esm-apps",
                            "entitled": false
                        }
                    ]
                }
            }
        }
        """
        And I append the following on uaclient config:
        """
        features:
          machine_token_overlay: "/tmp/machine-token-overlay.json"
        """
        And I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        Ubuntu Pro: ESM Infra enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        esm-infra    +yes      +enabled  +Expanded Security Maintenance for Infrastructure
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | fips_status |lp_status | lp_desc                       | cc_status | cis_or_usg | cis_status |
           | xenial  | disabled    |enabled   | Canonical Livepatch service   | disabled  | cis        | disabled   |
           | bionic  | disabled    |enabled   | Canonical Livepatch service   | disabled  | cis        | disabled   |
           | focal   | disabled    |enabled   | Canonical Livepatch service   | n/a       | usg        | disabled   |
           | jammy   | n/a         |enabled   | Canonical Livepatch service   | n/a       | usg        | n/a        |

    @series.all
    @uses.config.machine_type.azure.generic
    Scenario Outline: Attach command in an generic Azure Ubuntu VM
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I create the file `/tmp/machine-token-overlay.json` with the following:
        """
        {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {
                            "type": "esm-apps",
                            "entitled": false
                        }
                    ]
                }
            }
        }
        """
        And I append the following on uaclient config:
        """
        features:
          machine_token_overlay: "/tmp/machine-token-overlay.json"
        """
        And I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        Ubuntu Pro: ESM Infra enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        esm-infra    +yes      +enabled  +Expanded Security Maintenance for Infrastructure
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | lp_status | fips_status | cc_status | cis_or_usg | cis_status |
           | xenial  | enabled   | disabled    | disabled  | cis        | disabled   |
           | bionic  | enabled   | disabled    | disabled  | cis        | disabled   |
           | focal   | enabled   | disabled    | n/a       | usg        | disabled   |
           | jammy   | enabled   | n/a         | n/a       | usg        | n/a        |

    @series.all
    @uses.config.machine_type.gcp.generic
    Scenario Outline: Attach command in an generic GCP Ubuntu VM
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I create the file `/tmp/machine-token-overlay.json` with the following:
        """
        {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {
                            "type": "esm-apps",
                            "entitled": false
                        }
                    ]
                }
            }
        }
        """
        And I append the following on uaclient config:
        """
        features:
          machine_token_overlay: "/tmp/machine-token-overlay.json"
        """
        And I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        Ubuntu Pro: ESM Infra enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        esm-infra    +yes      +enabled  +Expanded Security Maintenance for Infrastructure
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | lp_status | fips_status | cc_status | cis_or_usg | cis_status |
           | xenial  | n/a       | n/a         | disabled  | cis        | disabled   |
           | bionic  | enabled   | disabled    | disabled  | cis        | disabled   |
           | focal   | enabled   | disabled    | n/a       | usg        | disabled   |
           | jammy   | enabled   | n/a         | n/a       | usg        | n/a        |

    @series.all
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attach command with json output
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I verify that running attach `as non-root` with json response exits `1`
        Then I will see the following on stdout:
            """
            {"_schema_version": "0.1", "errors": [{"message": "This command must be run as root (try using sudo).", "message_code": "nonroot-user", "service": null, "type": "system"}], "failed_services": [], "needs_reboot": false, "processed_services": [], "result": "failure", "warnings": []}
            """
        When I verify that running attach `with sudo` with json response exits `0`
        Then I will see the following on stdout:
            """
            {"_schema_version": "0.1", "errors": [], "failed_services": [], "needs_reboot": false, "processed_services": ["esm-apps", "esm-infra"], "result": "success", "warnings": []}
            """
        When I run `pro status` with sudo
        Then stdout matches regexp:
        """
        esm-apps      +yes +enabled +Expanded Security Maintenance for Applications
        esm-infra     +yes +enabled +Expanded Security Maintenance for Infrastructure
        """

        Examples: ubuntu release
          | release | cc-eal   |
          | xenial  | disabled |
          | bionic  | disabled |
          | focal   | n/a      |
          | jammy   | n/a      |

    @series.all
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attach and Check for contract change in status checking
       Given a `<release>` machine with ubuntu-advantage-tools installed
       When I attach `contract_token` with sudo
       Then stdout matches regexp:
       """
       Ubuntu Pro: ESM Infra enabled
       """
       And stdout matches regexp:
       """
       This machine is now attached to
       """
       And stdout matches regexp:
       """
       esm-infra    +yes      +enabled  +Expanded Security Maintenance for Infrastructure
       """
       When I create the file `/tmp/machine-token-overlay.json` with the following:
       """
       {
           "machineTokenInfo": {
               "contractInfo": {
                   "effectiveTo": "2000-01-02T03:04:05Z"
               }
           }
       }
       """
       And I append the following on uaclient config:
       """
       features:
         machine_token_overlay: "/tmp/machine-token-overlay.json"
       """
       When I run `pro status` with sudo
       Then stdout matches regexp:
       """
       A change has been detected in your contract.
       Please run `sudo pro refresh`.
       """
       When I run `pro refresh contract` with sudo
       Then stdout matches regexp:
       """
       Successfully refreshed your subscription.
       """
       When I run `sed -i '/^.*machine_token_overlay:/d' /etc/ubuntu-advantage/uaclient.conf` with sudo
       And I run `pro status` with sudo
       Then stdout does not match regexp:
       """
       A change has been detected in your contract.
       Please run `sudo pro refresh`.
       """

        Examples: ubuntu release livepatch status
           | release |
           | xenial  |
           | bionic  |
           | focal   |
