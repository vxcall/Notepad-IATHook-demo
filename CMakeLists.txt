cmake_minimum_required(VERSION 3.0.0)
project(Notepad-IATHook-demo VERSION 0.1.0)

include(CTest)
enable_testing()

file(GLOB_RECURSE MAIN ${CMAKE_CURRENT_SOURCE_DIR}/Notepad-IATHook-demo/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/Notepad-IATHook-demo/*.h)

add_executable(Notepad-IATHook-demo ${MAIN})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
