/*

Copyright (C) 2022 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#pragma once

/* taken from driver/API_VERSION */
#define PPM_API_CURRENT_VERSION_MAJOR 5
#define PPM_API_CURRENT_VERSION_MINOR 0
#define PPM_API_CURRENT_VERSION_PATCH 0

/* taken from driver/SCHEMA_VERSION */
#define PPM_SCHEMA_CURRENT_VERSION_MAJOR 2
#define PPM_SCHEMA_CURRENT_VERSION_MINOR 10
#define PPM_SCHEMA_CURRENT_VERSION_PATCH 0

#include "ppm_api_version.h"

#define DRIVER_VERSION "6.0.1+driver"

#define DRIVER_NAME "scap"

#define DRIVER_DEVICE_NAME "scap"

#define DRIVER_COMMIT "bcb417fdbb824208633c29638e1d1e211cf85cc3"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME DRIVER_NAME
#endif
