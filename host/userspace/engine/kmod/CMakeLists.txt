include_directories(${LIBSCAP_INCLUDE_DIRS})
include_directories("/opt/mellanox/doca/applications/common/src")
include_directories("/opt/mellanox/doca/applications/dma_copy")
include_directories("/opt/mellanox/doca/applications/dma_copy/src")
include_directories("/opt/mellanox/doca")


#link_directories(/opt/mellanox/doca/lib/x86_64-linux-gnu)
#link_directories(/opt/mellanox/doca/applications/dma_copy/src)
add_library(scap_engine_kmod scap_kmod.c /opt/mellanox/doca/applications/dma_copy/src/dma_copy_core.c /opt/mellanox/doca/applications/common/src/pack.c /opt/mellanox/doca/applications/common/src/utils.c /opt/mellanox/doca/samples/common.c /opt/mellanox/doca/applications/dma_copy/src/dma_copy.c)

# find_package(PkgConfig REQUIRED)
# pkg_check_modules(MY_DEPENDENCY REQUIRED doca)

target_compile_options(scap_engine_kmod PRIVATE -Wno-missing-braces -Wno-missing-field-initializers)
target_include_directories(scap_engine_kmod PRIVATE ${MY_DEPENDENCY_INCLUDE_DIRS} "/opt/mellanox/doca/include")


target_link_libraries(scap_engine_kmod scap_event_schema scap_platform scap_engine_util scap_error ${MY_DEPENDENCY_LIBRARIES} /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_common.so.2 /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_argp.so.2 /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_dma.so.2 /opt/mellanox/doca/lib/x86_64-linux-gnu/libdoca_comm_channel.so.2)
add_dependencies(scap_engine_kmod scap_event_schema scap_platform scap_engine_util scap_error ${MY_DEPENDENCY_LIBRARIES})
set_scap_target_properties(scap_engine_kmod)
