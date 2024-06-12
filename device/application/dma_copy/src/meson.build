#
# Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_APPLICATIONS', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

install_apps = false
APP_NAME = 'dma_copy'
common_path = '/opt/mellanox/doca/applications/common/src'
common_dir_path = common_path
samples_dir_path = '/opt/mellanox/doca/samples'
app_dependencies = []
app_srcs = []
base_c_args = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
]

app_dependencies += dependency('doca')

app_srcs += [
	'dma_copy_core.c',
	common_dir_path + '/pack.c',
	common_dir_path + '/utils.c',
	samples_dir_path + '/common.c',
]

vanilla_app_srcs = [
	APP_NAME + '.c',
]


app_inc_dirs = [
	include_directories(common_path),
	include_directories('../../..'),
	include_directories('..'),
]

executable('doca_' + APP_NAME,
	   app_srcs + vanilla_app_srcs,
	   c_args : base_c_args,
	   dependencies : app_dependencies,
	   include_directories : app_inc_dirs,
	   install: install_apps)
