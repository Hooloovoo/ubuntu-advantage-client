@uses.config.contract_token
Feature: Livepatch

    @series.focal
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached livepatch status shows warning when on unsupported kernel
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I create the file `/etc/ubuntu-advantage/uaclient.conf` with the following:
        """
        livepatch_url: 'https://livepatch.staging.canonical.com'
        """
        When I attach `contract_token` with sudo
        When I run `pro status` with sudo
        Then stdout matches regexp:
        """
        livepatch +yes +warning +Current kernel is not supported
        """
        Then stdout matches regexp:
        """
        NOTICES:
        The current kernel (5.4.0-27-kvm, x86_64) is not supported by livepatch.
        Supported kernels are listed here: https://ubuntu.com/security/livepatch/docs/kernels
        Either switch to a supported kernel or `pro disable livepatch` to dismiss this warning.

        """
        Examples: ubuntu release
            | release |
            | focal  |
