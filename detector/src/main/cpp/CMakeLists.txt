cmake_minimum_required(VERSION 3.22.1)

project("ifconfigdetector")

add_library(
        ifconfigdetector
        SHARED
        ifconfigdetector.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        ifconfigdetector
        ${log-lib}
)
