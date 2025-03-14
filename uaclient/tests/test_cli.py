import contextlib
import io
import json
import logging
import os
import re
import socket
import stat
import sys
import textwrap

import mock
import pytest

from uaclient import exceptions, messages, status
from uaclient.cli import (
    action_help,
    assert_attached,
    assert_lock_file,
    assert_not_attached,
    assert_root,
    get_parser,
    main,
    setup_logging,
)
from uaclient.entitlements import get_valid_entitlement_names
from uaclient.exceptions import (
    AlreadyAttachedError,
    LockHeldError,
    NonRootUserError,
    UnattachedError,
    UserFacingError,
)

BIG_DESC = "123456789 " * 7 + "next line"
BIG_URL = "http://" + "adsf" * 10

AVAILABLE_RESOURCES = [
    {"name": "cc-eal"},
    {"name": "cis"},
    {"name": "esm-apps"},
    {"name": "esm-infra"},
    {"name": "fips-updates"},
    {"name": "fips"},
    {"name": "livepatch"},
    {"name": "ros-updates"},
    {"name": "ros"},
]

ALL_SERVICES_WRAPPED_HELP = textwrap.dedent(
    """
Client to manage Ubuntu Pro services on a machine.
 - cc-eal: Common Criteria EAL2 Provisioning Packages
   (https://ubuntu.com/cc-eal)
 - cis: Security compliance and audit tools
   (https://ubuntu.com/security/certifications/docs/usg)
 - esm-apps: Expanded Security Maintenance for Applications
   (https://ubuntu.com/security/esm)
 - esm-infra: Expanded Security Maintenance for Infrastructure
   (https://ubuntu.com/security/esm)
 - fips-updates: NIST-certified core packages with priority security updates
   (https://ubuntu.com/security/certifications#fips)
 - fips: NIST-certified core packages
   (https://ubuntu.com/security/certifications#fips)
 - livepatch: Canonical Livepatch service
   (https://ubuntu.com/security/livepatch)
 - ros-updates: All Updates for the Robot Operating System
   (https://ubuntu.com/robotics/ros-esm)
 - ros: Security Updates for the Robot Operating System
   (https://ubuntu.com/robotics/ros-esm)
"""
)

SERVICES_WRAPPED_HELP = textwrap.dedent(
    """
Client to manage Ubuntu Pro services on a machine.
 - cc-eal: Common Criteria EAL2 Provisioning Packages
   (https://ubuntu.com/cc-eal)
 - cis: Security compliance and audit tools
   (https://ubuntu.com/security/certifications/docs/usg)
 - esm-apps: Expanded Security Maintenance for Applications
   (https://ubuntu.com/security/esm)
 - esm-infra: Expanded Security Maintenance for Infrastructure
   (https://ubuntu.com/security/esm)
 - fips-updates: NIST-certified core packages with priority security updates
   (https://ubuntu.com/security/certifications#fips)
 - fips: NIST-certified core packages
   (https://ubuntu.com/security/certifications#fips)
 - livepatch: Canonical Livepatch service
   (https://ubuntu.com/security/livepatch)
"""
)


@pytest.fixture(params=["direct", "--help", "pro help", "pro help --all"])
def get_help(request, capsys, FakeConfig):
    cfg = FakeConfig()
    if request.param == "direct":

        def _get_help_output():
            with mock.patch(
                "uaclient.config.UAConfig",
                return_value=FakeConfig(),
            ):
                parser = get_parser(cfg)
                help_file = io.StringIO()
                parser.print_help(file=help_file)
                return (help_file.getvalue(), "base")

    elif request.param == "--help":

        def _get_help_output():
            parser = get_parser(cfg)
            with mock.patch("sys.argv", ["pro", "--help"]):
                with mock.patch(
                    "uaclient.config.UAConfig",
                    return_value=FakeConfig(),
                ):
                    with pytest.raises(SystemExit):
                        parser.parse_args()
            out, _err = capsys.readouterr()
            return (out, "base")

    elif "help" in request.param:

        def _get_help_output():
            with mock.patch("sys.argv", request.param.split(" ")):
                with mock.patch(
                    "uaclient.config.UAConfig",
                    return_value=FakeConfig(),
                ):
                    main()
            out, _err = capsys.readouterr()

            if "--all" in request.param:
                return (out, "all")

            return (out, "base")

    else:
        raise NotImplementedError("Unknown help source: {}", request.param)
    return _get_help_output


class TestCLIParser:
    maxDiff = None

    @mock.patch("uaclient.cli.entitlements")
    @mock.patch("uaclient.cli.contract")
    def test_help_descr_and_url_is_wrapped_at_eighty_chars(
        self, m_contract, m_entitlements, get_help
    ):
        """Help lines are wrapped at 80 chars"""

        mocked_ent = mock.MagicMock(
            presentation_name="test",
            description=BIG_DESC,
            help_doc_url=BIG_URL,
            is_beta=False,
        )

        m_entitlements.entitlement_factory.return_value = mocked_ent
        m_contract.get_available_resources.return_value = [{"name": "test"}]

        lines = [
            " - test: " + " ".join(["123456789"] * 7),
            "   next line ({url})".format(url=BIG_URL),
        ]
        out, _ = get_help()
        assert "\n".join(lines) in out

    @mock.patch("uaclient.cli.contract")
    def test_help_sourced_dynamically_from_each_entitlement(
        self, m_contract, get_help
    ):
        """Help output is sourced from entitlement name and description."""
        m_contract.get_available_resources.return_value = AVAILABLE_RESOURCES
        out, type_request = get_help()
        if type_request == "base":
            assert SERVICES_WRAPPED_HELP in out
        else:
            assert ALL_SERVICES_WRAPPED_HELP in out

    @pytest.mark.parametrize(
        "out_format, expected_return",
        (
            (
                "tabular",
                "\n\n".join(
                    ["Name:\ntest", "Available:\nyes", "Help:\nTest\n\n"]
                ),
            ),
            ("json", {"name": "test", "available": "yes", "help": "Test"}),
        ),
    )
    @mock.patch("uaclient.status.get_available_resources")
    @mock.patch(
        "uaclient.config.UAConfig.is_attached", new_callable=mock.PropertyMock
    )
    def test_help_command_when_unnatached(
        self, m_attached, m_available_resources, out_format, expected_return
    ):
        """
        Test help command for a valid service in an unattached pro client.
        """
        m_args = mock.MagicMock()
        m_service_name = mock.PropertyMock(return_value="test")
        type(m_args).service = m_service_name
        m_format = mock.PropertyMock(return_value=out_format)
        type(m_args).format = m_format
        m_all = mock.PropertyMock(return_value=True)
        type(m_args).all = m_all

        m_entitlement_cls = mock.MagicMock()
        m_ent_help_info = mock.PropertyMock(return_value="Test")
        m_entitlement_obj = m_entitlement_cls.return_value
        type(m_entitlement_obj).help_info = m_ent_help_info

        m_attached.return_value = False

        m_available_resources.return_value = [
            {"name": "test", "available": True}
        ]

        fake_stdout = io.StringIO()
        with mock.patch(
            "uaclient.status.entitlement_factory",
            return_value=m_entitlement_cls,
        ):
            with contextlib.redirect_stdout(fake_stdout):
                action_help(m_args, cfg=None)

        if out_format == "tabular":
            assert expected_return.strip() == fake_stdout.getvalue().strip()
        else:
            assert expected_return == json.loads(fake_stdout.getvalue())

        assert 1 == m_service_name.call_count
        assert 1 == m_ent_help_info.call_count
        assert 1 == m_available_resources.call_count
        assert 1 == m_attached.call_count
        assert 1 == m_format.call_count

    @pytest.mark.parametrize(
        "ent_status, ent_msg",
        (
            (status.ContractStatus.ENTITLED, "yes"),
            (status.ContractStatus.UNENTITLED, "no"),
        ),
    )
    @pytest.mark.parametrize("is_beta", (True, False))
    @mock.patch("uaclient.status.get_available_resources")
    @mock.patch(
        "uaclient.config.UAConfig.is_attached", new_callable=mock.PropertyMock
    )
    def test_help_command_when_attached(
        self, m_attached, m_available_resources, ent_status, ent_msg, is_beta
    ):
        """Test help command for a valid service in an attached pro client."""
        m_args = mock.MagicMock()
        m_service_name = mock.PropertyMock(return_value="test")
        type(m_args).service = m_service_name
        m_all = mock.PropertyMock(return_value=True)
        type(m_args).all = m_all

        m_entitlement_cls = mock.MagicMock()
        m_ent_help_info = mock.PropertyMock(
            return_value="Test service\nService is being tested"
        )
        m_is_beta = mock.PropertyMock(return_value=is_beta)
        type(m_entitlement_cls).is_beta = m_is_beta
        m_entitlement_obj = m_entitlement_cls.return_value
        type(m_entitlement_obj).help_info = m_ent_help_info

        m_entitlement_obj.contract_status.return_value = ent_status
        m_entitlement_obj.user_facing_status.return_value = (
            status.UserFacingStatus.ACTIVE,
            messages.NamedMessage("test-code", "active"),
        )
        m_ent_name = mock.PropertyMock(return_value="test")
        type(m_entitlement_obj).name = m_ent_name
        m_ent_desc = mock.PropertyMock(return_value="description")
        type(m_entitlement_obj).description = m_ent_desc

        m_attached.return_value = True
        m_available_resources.return_value = [
            {"name": "test", "available": True}
        ]

        status_msg = "enabled" if ent_msg == "yes" else "—"
        ufs_call_count = 1 if ent_msg == "yes" else 0
        ent_name_call_count = 2 if ent_msg == "yes" else 1
        is_beta_call_count = 1 if status_msg == "enabled" else 0

        expected_msgs = [
            "Name:\ntest",
            "Entitled:\n{}".format(ent_msg),
            "Status:\n{}".format(status_msg),
        ]

        if is_beta and status_msg == "enabled":
            expected_msgs.append("Beta:\nTrue")

        expected_msgs.append(
            "Help:\nTest service\nService is being tested\n\n"
        )

        expected_msg = "\n\n".join(expected_msgs)

        fake_stdout = io.StringIO()
        with mock.patch(
            "uaclient.status.entitlement_factory",
            return_value=m_entitlement_cls,
        ):
            with contextlib.redirect_stdout(fake_stdout):
                action_help(m_args, cfg=None)

        assert expected_msg.strip() == fake_stdout.getvalue().strip()
        assert 1 == m_service_name.call_count
        assert 1 == m_ent_help_info.call_count
        assert 1 == m_available_resources.call_count
        assert 1 == m_attached.call_count
        assert 1 == m_ent_desc.call_count
        assert is_beta_call_count == m_is_beta.call_count
        assert ent_name_call_count == m_ent_name.call_count
        assert 1 == m_entitlement_obj.contract_status.call_count
        assert (
            ufs_call_count == m_entitlement_obj.user_facing_status.call_count
        )

    @mock.patch("uaclient.status.get_available_resources")
    def test_help_command_for_invalid_service(self, m_available_resources):
        """Test help command when an invalid service is provided."""
        m_args = mock.MagicMock()
        m_service_name = mock.PropertyMock(return_value="test")
        type(m_args).service = m_service_name
        m_all = mock.PropertyMock(return_value=True)
        type(m_args).all = m_all

        m_available_resources.return_value = [
            {"name": "ent1", "available": True}
        ]

        fake_stdout = io.StringIO()
        with contextlib.redirect_stdout(fake_stdout):
            with pytest.raises(UserFacingError) as excinfo:
                action_help(m_args, cfg=None)

        assert "No help available for 'test'" == str(excinfo.value)
        assert 1 == m_service_name.call_count
        assert 1 == m_available_resources.call_count


M_PATH_UACONFIG = "uaclient.config.UAConfig."


class TestAssertLockFile:
    @mock.patch("os.getpid", return_value=123)
    @mock.patch(M_PATH_UACONFIG + "delete_cache_key")
    @mock.patch("uaclient.files.NoticeFile.add")
    @mock.patch(M_PATH_UACONFIG + "write_cache")
    def test_assert_root_creates_lock_and_notice(
        self,
        m_write_cache,
        m_add_notice,
        m_remove_notice,
        _m_getpid,
        FakeConfig,
    ):
        arg, kwarg = mock.sentinel.arg, mock.sentinel.kwarg

        @assert_lock_file("some operation")
        def test_function(args, cfg):
            assert arg == mock.sentinel.arg
            assert kwarg == mock.sentinel.kwarg

            return mock.sentinel.success

        ret = test_function(arg, cfg=FakeConfig())
        assert mock.sentinel.success == ret
        lock_msg = "Operation in progress: some operation"
        assert [mock.call("", lock_msg)] == m_add_notice.call_args_list
        assert [mock.call("lock")] == m_remove_notice.call_args_list
        assert [
            mock.call("lock", "123:some operation")
        ] == m_write_cache.call_args_list


class TestAssertRoot:
    def test_assert_root_when_root(self):
        arg, kwarg = mock.sentinel.arg, mock.sentinel.kwarg

        @assert_root
        def test_function(arg, *, kwarg):
            assert arg == mock.sentinel.arg
            assert kwarg == mock.sentinel.kwarg

            return mock.sentinel.success

        with mock.patch("uaclient.cli.os.getuid", return_value=0):
            ret = test_function(arg, kwarg=kwarg)

        assert mock.sentinel.success == ret

    def test_assert_root_when_not_root(self):
        @assert_root
        def test_function():
            pass

        with mock.patch("uaclient.cli.os.getuid", return_value=1000):
            with pytest.raises(NonRootUserError):
                test_function()


# Test multiple uids, to be sure that the root checking is absent
@pytest.mark.parametrize("uid", [0, 1000])
class TestAssertAttached:
    def test_assert_attached_when_attached(self, capsys, uid, FakeConfig):
        @assert_attached()
        def test_function(args, cfg):
            return mock.sentinel.success

        cfg = FakeConfig.for_attached_machine()

        with mock.patch("uaclient.cli.os.getuid", return_value=uid):
            ret = test_function(mock.Mock(), cfg)

        assert mock.sentinel.success == ret

        out, _err = capsys.readouterr()
        assert "" == out.strip()

    def test_assert_attached_when_unattached(self, uid, FakeConfig):
        @assert_attached()
        def test_function(args, cfg):
            pass

        cfg = FakeConfig()

        with mock.patch("uaclient.cli.os.getuid", return_value=uid):
            with pytest.raises(UnattachedError):
                test_function(mock.Mock(), cfg)


@pytest.mark.parametrize("uid", [0, 1000])
class TestAssertNotAttached:
    def test_when_attached(self, uid, FakeConfig):
        @assert_not_attached
        def test_function(args, cfg):
            pass

        cfg = FakeConfig.for_attached_machine()

        with mock.patch("uaclient.cli.os.getuid", return_value=uid):
            with pytest.raises(AlreadyAttachedError):
                test_function(mock.Mock(), cfg)

    def test_when_not_attached(self, capsys, uid, FakeConfig):
        @assert_not_attached
        def test_function(args, cfg):
            return mock.sentinel.success

        cfg = FakeConfig()

        with mock.patch("uaclient.cli.os.getuid", return_value=uid):
            ret = test_function(mock.Mock(), cfg)

        assert mock.sentinel.success == ret

        out, _err = capsys.readouterr()
        assert "" == out.strip()


class TestMain:
    @pytest.mark.parametrize(
        "exception,expected_error_msg,expected_log",
        (
            (
                TypeError("'NoneType' object is not subscriptable"),
                messages.UNEXPECTED_ERROR.msg + "\n",
                "Unhandled exception, please file a bug",
            ),
        ),
    )
    @mock.patch(M_PATH_UACONFIG + "delete_cache_key")
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    def test_errors_handled_gracefully(
        self,
        m_get_parser,
        _m_setup_logging,
        m_delete_cache_key,
        capsys,
        logging_sandbox,
        caplog_text,
        event,
        exception,
        expected_error_msg,
        expected_log,
        FakeConfig,
    ):
        m_args = m_get_parser.return_value.parse_args.return_value
        m_args.action.side_effect = exception

        with pytest.raises(SystemExit) as excinfo:
            with mock.patch("sys.argv", ["/usr/bin/ua", "subcmd"]):
                with mock.patch(
                    "uaclient.config.UAConfig",
                    return_value=FakeConfig(),
                ):
                    main()
        assert 0 == m_delete_cache_key.call_count

        exc = excinfo.value
        assert 1 == exc.code

        out, err = capsys.readouterr()
        assert "" == out
        assert expected_error_msg == err
        error_log = caplog_text()
        assert "Traceback (most recent call last):" in error_log
        assert expected_log in error_log

    @pytest.mark.parametrize(
        "exception,expected_error_msg,expected_log",
        (
            (
                KeyboardInterrupt,
                "Interrupt received; exiting.\n",
                "KeyboardInterrupt",
            ),
        ),
    )
    @mock.patch(M_PATH_UACONFIG + "delete_cache_key")
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    def test_interrupt_errors_handled_gracefully(
        self,
        m_get_parser,
        _m_setup_logging,
        m_delete_cache_key,
        capsys,
        logging_sandbox,
        caplog_text,
        exception,
        expected_error_msg,
        expected_log,
        FakeConfig,
    ):
        m_args = m_get_parser.return_value.parse_args.return_value
        m_args.action.side_effect = exception

        with pytest.raises(SystemExit) as excinfo:
            with mock.patch("sys.argv", ["/usr/bin/ua", "subcmd"]):
                with mock.patch(
                    "uaclient.config.UAConfig",
                    return_value=FakeConfig(),
                ):
                    main()
        assert 0 == m_delete_cache_key.call_count

        exc = excinfo.value
        assert 1 == exc.code

        out, err = capsys.readouterr()
        assert "" == out
        assert expected_error_msg == err
        error_log = caplog_text()
        assert expected_log in error_log

    @pytest.mark.parametrize(
        "exception,expected_exit_code",
        [
            (UserFacingError("You need to know about this."), 1),
            (AlreadyAttachedError(mock.MagicMock()), 2),
            (
                LockHeldError(
                    pid="123",
                    lock_request="pro reboot-cmds",
                    lock_holder="pro auto-attach",
                ),
                1,
            ),
        ],
    )
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    def test_user_facing_error_handled_gracefully(
        self,
        m_get_parser,
        _m_setup_logging,
        capsys,
        logging_sandbox,
        caplog_text,
        event,
        exception,
        expected_exit_code,
    ):
        m_args = m_get_parser.return_value.parse_args.return_value
        m_args.action.side_effect = exception
        expected_msg = exception.msg

        with pytest.raises(SystemExit) as excinfo:
            main(["some", "args"])

        exc = excinfo.value
        assert expected_exit_code == exc.code

        out, err = capsys.readouterr()
        assert "" == out
        assert "{}\n".format(expected_msg) == err
        error_log = caplog_text()
        # pytest 4.6.x started indenting trailing lines in log messages, which
        # meant that our matching here stopped working once we introduced
        # newlines into this log output in #973.  (If focal moves onto pytest
        # 5.x before release, then we can remove this workaround.)  The
        # upstream issue is https://github.com/pytest-dev/pytest/issues/5515
        error_log = "\n".join(
            [line.strip() for line in error_log.splitlines()]
        )
        assert expected_msg in error_log
        assert "Traceback (most recent call last):" not in error_log

    @pytest.mark.parametrize(
        "error_url,expected_log",
        (
            (
                None,
                "Check your Internet connection and try again."
                " [Errno -2] Name or service not known",
            ),
            (
                "http://nowhere.com",
                "Check your Internet connection and try again."
                " Failed to access URL: http://nowhere.com."
                " [Errno -2] Name or service not known",
            ),
        ),
    )
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    def test_url_error_handled_gracefully(
        self,
        m_get_parser,
        _m_setup_logging,
        error_url,
        expected_log,
        capsys,
        logging_sandbox,
        caplog_text,
    ):

        m_args = m_get_parser.return_value.parse_args.return_value
        m_args.action.side_effect = exceptions.UrlError(
            socket.gaierror(-2, "Name or service not known"), url=error_url
        )

        with pytest.raises(SystemExit) as excinfo:
            main(["some", "args"])

        exc = excinfo.value
        assert 1 == exc.code

        out, err = capsys.readouterr()
        assert "" == out
        assert "{}\n".format(messages.CONNECTIVITY_ERROR.msg) == err
        error_log = caplog_text()

        assert expected_log in error_log
        assert "Traceback (most recent call last):" in error_log

    @pytest.mark.parametrize("caplog_text", [logging.DEBUG], indirect=True)
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    def test_command_line_is_logged(
        self, _m_get_parser, _m_setup_logging, logging_sandbox, caplog_text
    ):
        main(["some", "args"])

        log = caplog_text()

        assert "['some', 'args']" in log

    @pytest.mark.parametrize("caplog_text", [logging.DEBUG], indirect=True)
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.get_parser")
    @mock.patch(
        "uaclient.cli.util.get_pro_environment",
        return_value={"UA_ENV": "YES", "UA_FEATURES_WOW": "XYZ"},
    )
    def test_environment_is_logged(
        self,
        _m_pro_environment,
        _m_get_parser,
        _m_setup_logging,
        logging_sandbox,
        caplog_text,
    ):
        main(["some", "args"])

        log = caplog_text()

        assert "UA_ENV=YES" in log
        assert "UA_FEATURES_WOW=XYZ" in log

    @mock.patch("uaclient.cli.contract.get_available_resources")
    def test_argparse_errors_well_formatted(
        self, _m_resources, capsys, FakeConfig
    ):
        cfg = FakeConfig()
        parser = get_parser(cfg)
        with mock.patch("sys.argv", ["pro", "enable"]):
            with pytest.raises(SystemExit) as excinfo:
                parser.parse_args()
        assert 2 == excinfo.value.code
        _, err = capsys.readouterr()
        assert (
            textwrap.dedent(
                """\
            usage: pro enable <service> [<service>] [flags]
            the following arguments are required: service
        """
            )
            == str(err)
        )


class TestSetupLogging:
    @pytest.mark.parametrize("level", (logging.INFO, logging.ERROR))
    def test_console_log_configured_if_not_present(
        self, level, capsys, logging_sandbox
    ):
        setup_logging(level, logging.INFO)
        logging.log(level, "after setup")
        logging.log(level - 1, "not present")

        _, err = capsys.readouterr()
        assert "after setup" in err
        assert "not present" not in err

    def test_console_log_configured_if_already_present(
        self, capsys, logging_sandbox
    ):
        logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))

        logging.error("before setup")
        setup_logging(logging.INFO, logging.INFO)
        logging.error("after setup")

        # 'before setup' will be in stderr, so check that setup_logging
        # configures the format
        _, err = capsys.readouterr()
        assert "ERROR: before setup" not in err
        assert "ERROR: after setup" in err

    @mock.patch("uaclient.cli.os.getuid", return_value=100)
    def test_file_log_not_configured_if_not_root(
        self, m_getuid, tmpdir, logging_sandbox
    ):
        log_file = tmpdir.join("log_file")

        setup_logging(logging.INFO, logging.INFO, log_file=log_file.strpath)
        logging.info("after setup")

        assert not log_file.exists()

    @pytest.mark.parametrize("log_filename", (None, "file.log"))
    @mock.patch("uaclient.cli.os.getuid", return_value=0)
    @mock.patch("uaclient.cli.config")
    def test_file_log_configured_if_root(
        self, m_config, _m_getuid, log_filename, logging_sandbox, tmpdir
    ):
        if log_filename is None:
            log_filename = "default.log"
            log_file = tmpdir.join(log_filename)
            m_config.CONFIG_DEFAULTS = {"log_file": log_file.strpath}
        else:
            log_file = tmpdir.join(log_filename)

        setup_logging(logging.INFO, logging.INFO, log_file=log_file.strpath)
        logging.info("after setup")

        assert "after setup" in log_file.read()

    @mock.patch("uaclient.cli.os.getuid", return_value=0)
    @mock.patch("uaclient.cli.config.UAConfig")
    def test_file_log_configured_if_already_present(
        self, m_config, _m_getuid, logging_sandbox, tmpdir, FakeConfig
    ):
        some_file = log_file = tmpdir.join("default.log")
        logging.getLogger().addHandler(logging.FileHandler(some_file.strpath))

        log_file = tmpdir.join("file.log")
        cfg = FakeConfig({"log_file": log_file.strpath})
        m_config.return_value = cfg

        logging.error("before setup")
        setup_logging(logging.INFO, logging.INFO)
        logging.error("after setup")

        content = log_file.read()
        assert "[ERROR]: before setup" not in content
        assert "[ERROR]: after setup" in content

    @mock.patch("uaclient.cli.config.UAConfig")
    @mock.patch("uaclient.cli.os.getuid", return_value=0)
    def test_custom_logger_configuration(
        self, m_getuid, m_config, logging_sandbox, tmpdir, FakeConfig
    ):
        log_file = tmpdir.join("file.log")
        cfg = FakeConfig({"log_file": log_file.strpath})
        m_config.return_value = cfg

        custom_logger = logging.getLogger("for-my-special-module")
        root_logger = logging.getLogger()
        n_root_handlers = len(root_logger.handlers)

        setup_logging(logging.INFO, logging.INFO, logger=custom_logger)

        assert len(custom_logger.handlers) == 2
        assert len(root_logger.handlers) == n_root_handlers

    @mock.patch("uaclient.cli.config.UAConfig")
    @mock.patch("uaclient.cli.os.getuid", return_value=0)
    def test_no_duplicate_ua_handlers(
        self, m_getuid, m_config, logging_sandbox, tmpdir, FakeConfig
    ):
        log_file = tmpdir.join("file.log")
        cfg = FakeConfig({"log_file": log_file.strpath})
        m_config.return_value = cfg
        root_logger = logging.getLogger()

        setup_logging(logging.INFO, logging.DEBUG)
        stream_handlers = [
            h
            for h in root_logger.handlers
            if h.level == logging.INFO and isinstance(h, logging.StreamHandler)
        ]
        file_handlers = [
            h
            for h in root_logger.handlers
            if h.level == logging.DEBUG
            and isinstance(h, logging.FileHandler)
            and h.stream.name == log_file
        ]
        assert len(root_logger.handlers) == 2
        assert len(stream_handlers) == 1
        assert len(file_handlers) == 1

        setup_logging(logging.INFO, logging.DEBUG)
        stream_handlers = [
            h
            for h in root_logger.handlers
            if h.level == logging.INFO and isinstance(h, logging.StreamHandler)
        ]
        file_handlers = [
            h
            for h in root_logger.handlers
            if h.level == logging.DEBUG
            and isinstance(h, logging.FileHandler)
            and h.stream.name == log_file
        ]
        assert len(root_logger.handlers) == 2
        assert len(stream_handlers) == 1
        assert len(file_handlers) == 1

    @pytest.mark.parametrize("pre_existing", (True, False))
    @mock.patch("uaclient.cli.os.getuid", return_value=0)
    @mock.patch("uaclient.cli.config")
    def test_file_log_is_world_readable(
        self, m_config, _m_getuid, logging_sandbox, tmpdir, pre_existing
    ):
        log_file = tmpdir.join("root-only.log")
        log_path = log_file.strpath
        expected_mode = 0o644
        if pre_existing:
            expected_mode = 0o640
            log_file.write("existing content\n")
            os.chmod(log_path, expected_mode)
            assert 0o644 != stat.S_IMODE(os.lstat(log_path).st_mode)

        setup_logging(logging.INFO, logging.INFO, log_file=log_path)
        logging.info("after setup")

        assert expected_mode == stat.S_IMODE(os.lstat(log_path).st_mode)
        log_content = log_file.read()
        assert "after setup" in log_content
        if pre_existing:
            assert "existing content" in log_content


class TestGetValidEntitlementNames:
    @mock.patch(
        "uaclient.cli.entitlements.valid_services",
        return_value=["ent1", "ent2", "ent3"],
    )
    def test_get_valid_entitlements(self, _m_valid_services, FakeConfig):
        service = ["ent1", "ent3", "ent4"]
        expected_ents_found = ["ent1", "ent3"]
        expected_ents_not_found = ["ent4"]

        actual_ents_found, actual_ents_not_found = get_valid_entitlement_names(
            service, cfg=FakeConfig()
        )

        assert expected_ents_found == actual_ents_found
        assert expected_ents_not_found == actual_ents_not_found


expected_notice = r""".*[info].* A new version is available: 1.2.3
Please run:
    sudo apt-get install ubuntu-advantage-tools
to get the latest version with new features and bug fixes.
"""


# There is a fixture for this function to avoid leaking, as it is called in
# the main CLI function. So, instead of importing it directly, we are using
# the reference for the fixture to test it.
class TestWarnAboutNewVersion:
    @pytest.mark.parametrize("new_version", (None, "1.2.3"))
    @pytest.mark.parametrize("caplog_text", [logging.WARNING], indirect=True)
    @mock.patch("uaclient.cli.version.check_for_new_version")
    def test_warn_about_new_version(
        self,
        m_check_version,
        new_version,
        caplog_text,
        _warn_about_new_version,
    ):
        m_check_version.return_value = new_version

        _warn_about_new_version()

        if new_version:
            assert re.search(expected_notice, caplog_text())
        else:
            assert not re.search(expected_notice, caplog_text())

    @pytest.mark.parametrize("command", ("api", "status"))
    @pytest.mark.parametrize("out_format", (None, "tabular", "json"))
    @pytest.mark.parametrize("caplog_text", [logging.WARNING], indirect=True)
    @mock.patch(
        "uaclient.cli.version.check_for_new_version", return_value="1.2.3"
    )
    def test_dont_show_for_api_calls(
        self,
        _m_check_version,
        caplog_text,
        command,
        out_format,
        _warn_about_new_version,
    ):
        args = mock.MagicMock()
        args.command = command
        args.format = out_format

        if not out_format:
            del args.format

        _warn_about_new_version(args)

        if command != "api" and out_format != "json":
            assert re.search(expected_notice, caplog_text())
        else:
            assert not re.search(expected_notice, caplog_text())
