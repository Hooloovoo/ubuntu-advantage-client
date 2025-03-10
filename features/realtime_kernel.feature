@uses.config.contract_token
Feature: Enable command behaviour when attached to an Ubuntu Pro subscription

    @series.jammy
    @uses.config.machine_type.lxd.container
    Scenario Outline: Enable Real-Time Kernel service in a container
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `pro enable realtime-kernel` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        Then I verify that running `pro enable realtime-kernel --beta` `with sudo` exits `1`
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            Cannot install Real-Time Kernel on a container.
            """
        Examples: ubuntu release
            | release |
            | jammy   |

    @series.lts
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Enable Real-Time Kernel service on unsupported release
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `pro enable realtime-kernel` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        Then I verify that running `pro enable realtime-kernel --beta` `with sudo` exits `1`
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            Real-Time Kernel is not available for Ubuntu <version> (<full_name>).
            """
        Examples: ubuntu release
            | release | version    | full_name       |
            | xenial  | 16.04 LTS  | Xenial Xerus    |
            | bionic  | 18.04 LTS  | Bionic Beaver   |
            | focal   | 20.04 LTS  | Focal Fossa     |

    @series.jammy
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Enable Real-Time Kernel service
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `pro enable realtime-kernel` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        Then I verify that running `pro enable realtime-kernel` `with sudo` exits `1`
        And stderr matches regexp:
            """
            Cannot enable unknown service 'realtime-kernel'.
            """
        When I run `pro enable realtime-kernel --beta` `with sudo` and stdin `y`
        Then stdout matches regexp:
            """
            One moment, checking your subscription first
            The real-time kernel is a beta version of the 22.04 Ubuntu kernel with the
            PREEMPT_RT patchset integrated for x86_64 and ARM64.

            .*This will change your kernel. You will need to manually configure grub to
            revert back to your original kernel after enabling real-time..*

            Do you want to continue\? \[ default = Yes \]: \(Y/n\) Updating package lists
            Installing Real-Time Kernel packages
            Real-Time Kernel enabled
            A reboot is required to complete install.
            """
        When I run `apt-cache policy ubuntu-realtime` as non-root
        Then stdout does not match regexp:
            """
            .*Installed: \(none\)
            """
        And stdout matches regexp:
            """
            \s* 500 https://esm.ubuntu.com/realtime/ubuntu <release>/main amd64 Packages
            """
        When I verify that running `pro enable realtime-kernel --beta` `with sudo` exits `1`
        Then stdout matches regexp
            """
            One moment, checking your subscription first
            Real-Time Kernel is already enabled.
            See: sudo pro status
            """
        When I reboot the machine
        When I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            realtime
            """
        When I run `pro disable realtime-kernel` `with sudo` and stdin `y`
        Then stdout matches regexp:
            """
            This will disable the Real-Time Kernel entitlement but the Real-Time Kernel will remain installed.
            """
        Examples: ubuntu release
            | release |
            | jammy   |

    @series.jammy
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Enable Real-Time Kernel service access-only
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        When I run `pro enable realtime-kernel --beta --access-only` with sudo
        Then stdout matches regexp:
        """
        One moment, checking your subscription first
        Updating package lists
        Skipping installing packages: ubuntu-realtime
        Real-Time Kernel access enabled
        """
        Then stdout does not match regexp:
        """
        A reboot is required to complete install.
        """
        When I run `apt-cache policy ubuntu-realtime` as non-root
        Then stdout matches regexp:
        """
        .*Installed: \(none\)
        """
        And stdout matches regexp:
        """
        \s* 500 https://esm.ubuntu.com/realtime/ubuntu <release>/main amd64 Packages
        """
        When I run `apt-get install -y ubuntu-realtime` with sudo
        When I reboot the machine
        When I run `uname -r` as non-root
        Then stdout matches regexp:
        """
        realtime
        """
        Examples: ubuntu release
            | release |
            | jammy   |
