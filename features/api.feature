Feature: Client behaviour for the API endpoints

    @series.all
    @uses.config.machine_type.lxd.container
    Scenario Outline: API invalid endpoint or args
    Given a `<release>` machine with ubuntu-advantage-tools installed
    When I verify that running `pro api invalid.endpoint` `with sudo` exits `1`
    Then stdout matches regexp:
    """
    {\"_schema_version\": \"v1\", \"data\": {\"meta\": {\"environment_vars\": \[]}}, \"errors\": \[{\"code\": \"api\-invalid\-endpoint", \"meta\": {}, \"title\": \"'invalid\.endpoint' is not a valid endpoint\"}], \"result\": \"failure\", \"version\": \".*\", \"warnings\": \[]}
    """
    When I verify that running `pro api u.pro.version.v1 --args extra=arg` `with sudo` exits `1`
    Then stdout matches regexp:
    """
    {\"_schema_version\": \"v1\", \"data\": {\"meta\": {\"environment_vars\": \[]}}, \"errors\": \[{\"code\": \"api\-no\-argument\-for\-endpoint\", \"meta\": {}, \"title\": \"u\.pro\.version\.v1 accepts no arguments\"}], \"result\": \"failure\", \"version\": \".*\", \"warnings\": \[]}
    """

    Examples: ubuntu release
           | release |
           | bionic  |
           | focal   |
           | xenial  |
           | jammy   |
           | kinetic |

    @series.all
    @uses.config.machine_type.lxd.container
    Scenario Outline: Basic endpoints
    Given a `<release>` machine with ubuntu-advantage-tools installed
    When I run `pro api u.pro.version.v1` with sudo
    Then stdout matches regexp:
    """
    {\"_schema_version\": \"v1\", \"data\": {\"attributes\": {\"installed_version\": \".*\"}, \"meta\": {\"environment_vars\": \[]}, \"type\": \"Version\"}, \"errors\": \[], \"result\": \"success\", \"version\": \".*\", \"warnings\": \[]}
    """
    When I run `UA_LOG_FILE=/tmp/some_file OTHER_ENVVAR=not_there pro api u.pro.version.v1` with sudo
    Then stdout matches regexp:
    """
    {\"_schema_version\": \"v1\", \"data\": {\"attributes\": {\"installed_version\": \".*\"}, \"meta\": {\"environment_vars\": \[{\"name\": \"UA_LOG_FILE\", \"value\": \"\/tmp\/some_file\"}]}, \"type\": \"Version\"}, \"errors\": \[], \"result\": \"success\", \"version\": \".*\", \"warnings\": \[]}
    """
    When I run `ua api u.pro.attach.auto.should_auto_attach.v1` with sudo
    Then stdout matches regexp:
    """
    {"_schema_version": "v1", "data": {"attributes": {"should_auto_attach": false}, "meta": {"environment_vars": \[\]}, "type": "ShouldAutoAttach"}, "errors": \[\], "result": "success", "version": ".*", "warnings": \[\]}
    """

    Examples: ubuntu release
           | release |
           | bionic  |
           | focal   |
           | xenial  |
           | jammy   |
           | kinetic |
