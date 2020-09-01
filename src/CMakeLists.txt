cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DANYCAST_ROAMING_VERSION=\\\"${CPACK_PACKAGE_VERSION}\\\"")

file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags"
	"\nccflags-y := ${CMAKE_C_FLAGS}\n" )

add_custom_target(KMODFILES ALL
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/anycast_roaming.ko)

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild"
	COMMAND cat 
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.default"
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags" 
		> "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags"
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.default"
	COMMENT "Create Kbuild")

# Build the module
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/anycast_roaming.ko
	COMMAND make -C ${KERNEL_SRCDIR} M=${CMAKE_CURRENT_SOURCE_DIR} modules
	DEPENDS core.c Kbuild
	COMMENT "Building anycast_roaming.ko")


# Installation of the module
set(module_install_path /lib/modules/${KERNEL_RELEASE}/kernel/extra/anycast_roaming)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/anycast_roaming.ko
        DESTINATION ${module_install_path}
        PERMISSIONS OWNER_READ OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)




