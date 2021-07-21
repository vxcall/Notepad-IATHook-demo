cmake_minimum_required(VERSION 3.16)
project(Notepad-IATHook-demo)
set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE MAIN ${CMAKE_CURRENT_SOURCE_DIR}/Notepad-IATHook-demo/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/Notepad-IATHook-demo/*.h)

add_library(${PROJECT_NAME} SHARED ${MAIN})