# !/usr/bin/env python
# -*- coding:utf-8 -*-


"""
logging handler.
"""

from __future__ import print_function
import inspect
import logging
import logging.config
import logging.handlers
import os
import sys
import ConfigParser

from oslo.config import cfg


CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.BoolOpt('verbose', default=False, help='Show DEBUG level log'),
    cfg.BoolOpt('use-stderr', default=True, help='Log to standard error'),
    cfg.StrOpt('log-dir', default=None, help='Log file directory'),
    cfg.StrOpt('log-file', default=None, help='Log file name'),
    cfg.StrOpt('log-file-mode', default='0644',
               help='Default log file permission'),
    cfg.StrOpt('log-config-file', default=None,
               help='Path to a logging config file to use')
])

DEBUG_LOG_FORMAT = '%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s ' \
                   '%(funcName)s %(lineno)d [-] %(message)s'
INFOR_LOG_FORMAT = '%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [-] %(message)s'
_EARLY_LOG_HANDLER = None


def early_init_log(level=None):
    global _EARLY_LOG_HANDLER
    _EARLY_LOG_HANDLER = logging.StreamHandler(sys.stderr)

    log = logging.getLogger()
    log.addHandler(_EARLY_LOG_HANDLER)
    if level is not None:
        log.setLevel(level)


def _get_log_file():
    if CONF.log_file:
        return CONF.log_file
    if CONF.log_dir:
        return os.path.join(CONF.log_dir,
                            os.path.basename(inspect.stack()[-1][1])) + '.log'
    return None


def _set_log_format(handlers, _format):
    for handler in handlers:
        handler.setFormatter(logging.Formatter(_format))


def init_log():
    global _EARLY_LOG_HANDLER

    log = logging.getLogger()
    if CONF.log_config_file:
        try:
            logging.config.fileConfig(CONF.log_config_file,
                                      disable_existing_loggers=False)
            if CONF.verbose:
                log.setLevel(logging.DEBUG)
                for handler in log.handlers:
                    handler.setFormatter(logging.Formatter(DEBUG_LOG_FORMAT))
        except ConfigParser.Error as e:
            print('Failed to parse %s: %s' % (CONF.log_config_file, e),
                  file=sys.stderr)
            sys.exit(2)
        return

    if CONF.use_stderr:
        log.addHandler(logging.StreamHandler(sys.stderr))
    if _EARLY_LOG_HANDLER is not None:
        log.removeHandler(_EARLY_LOG_HANDLER)
        _EARLY_LOG_HANDLER = None

    log_file = _get_log_file()
    if log_file is not None:
        log.addHandler(logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5))
        mode = int(CONF.log_file_mode, 8)
        os.chmod(log_file, mode)
        for handler in log.handlers:
                    handler.setFormatter(logging.Formatter(INFOR_LOG_FORMAT))

    if CONF.verbose:
        log.setLevel(logging.DEBUG)
        for handler in log.handlers:
                    handler.setFormatter(logging.Formatter(DEBUG_LOG_FORMAT))
    else:
        log.setLevel(logging.INFO)
        _set_log_format(log.handlers, INFOR_LOG_FORMAT)