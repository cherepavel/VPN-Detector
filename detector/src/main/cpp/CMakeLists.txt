cmake_minimum_required(VERSION 3.22.1)

project(ifconfigdetector LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

add_library(${PROJECT_NAME}
        SHARED
        ifconfigdetector.cpp
)

#for tests in Linux
if(NOT ANDROID)
    find_package(JNI REQUIRED)
    target_include_directories(${PROJECT_NAME} PRIVATE ${JNI_INCLUDE_DIRS})
endif ()

if(ANDROID)
    find_library(log-lib log)
    if(log-lib)
        target_link_libraries(${PROJECT_NAME} PRIVATE ${log-lib})
    endif()
    target_link_options(${PROJECT_NAME} PRIVATE -Wl,-z,max-page-size=16384)
endif()

target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -fPIC
        $<$<CONFIG:Release>:-O3 -DNDEBUG>
        $<$<CONFIG:Debug>:-g -O0>
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        OUTPUT_NAME ${PROJECT_NAME}
)