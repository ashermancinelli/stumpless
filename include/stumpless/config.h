/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright 2018-2023 Joel E. Anderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @dir config
 * Configuration-specific header files.
 */

/** @file
 * Configuration information to provide to code built with the library.
 */

#ifndef __STUMPLESS_CONFIG_H
#define __STUMPLESS_CONFIG_H

/** Marks functions that are provided for use by the library. */
#define STUMPLESS_PUBLIC_FUNCTION 

/** The facility code to use when one is not supplied. */
#define STUMPLESS_DEFAULT_FACILITY STUMPLESS_FACILITY_USER

/** The severity code to use when one is not supplied. */
#define STUMPLESS_DEFAULT_SEVERITY STUMPLESS_SEVERITY_INFO

/** A string literal with the default socket logged to. */
#define STUMPLESS_DEFAULT_SOCKET "/var/run/syslog"

/** The memory page size used for dynamic memory allocations. */
#define STUMPLESS_FALLBACK_PAGESIZE 4096

/** The language stumpless was built for, as an RFC 5646 language tag. */
#define STUMPLESS_LANGUAGE "en-US"

/** Defined if journald targets are supported by this build. */
/* #undef STUMPLESS_JOURNALD_TARGETS_SUPPORTED */

/** Defined if network targets are supported by this build. */
#define STUMPLESS_NETWORK_TARGETS_SUPPORTED 1

/** Defined if socket targets are supported by this build. */
#define STUMPLESS_SOCKET_TARGETS_SUPPORTED 1

/** Defined if colored output is enabled */
#define STUMPLESS_ANSI_COLOR_CODES_SUPPORTED 1

/** Default escape codes for each severity level */
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_EMERG    "\e[0;31m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_ALERT    "\e[0;33m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_CRIT     "\e[0;31m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_ERR      "\e[0;31m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_WARNING  "\e[0;33m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_NOTICE   "\e[0;36m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_INFO     "\e[0;36m"
#define STUMPLESS_DEFAULT_COLOR_CODE_FOR_SEVERITY_DEBUG    "\e[0;35m"

/**
 * A string literal with the name of the table used by default for SQLite3
 * targets.
 *
 * @since release v2.2.0
 */
#define STUMPLESS_DEFAULT_SQLITE3_TABLE_NAME_STRING                             \
"logs"

/**
 * The maximum number of retries for SQLite operations.
 *
 * @since release v2.2.0
 */
#define STUMPLESS_SQLITE3_RETRY_MAX 3

/** Defined if sqlite3 targets are supported by this build. */
#define STUMPLESS_SQLITE3_TARGETS_SUPPORTED 1

/** Defined if this build can directly replace syslog.h usage. */
#define STUMPLESS_SYSLOG_H_COMPATIBLE 1

/** Defined if thread-safe functionality is supported. */
#define STUMPLESS_THREAD_SAFETY_SUPPORTED 1

/** Defined if Windows Event Log targets are supported by this build. */
/* #undef STUMPLESS_WINDOWS_EVENT_LOG_TARGETS_SUPPORTED */

/** Defined if deprecation warnings are printed to standard output. */
#define STUMPLESS_DEPRECATION_WARNINGS_ENABLED 1

/** The major version of this stumpless build. */
#define STUMPLESS_MAJOR_VERSION 2

/** The minor version of this stumpless build. */
#define STUMPLESS_MINOR_VERSION 2

/** The patch version of this stumpless build. */
#define STUMPLESS_PATCH_VERSION 0

/**
 * The version of stumpless this library was built with.
 *
 * This will be in standard semantic versioning format: 'major.minor.patch'.
 */
#define STUMPLESS_VERSION "2.2.0"

#endif /* __STUMPLESS_CONFIG_H */
