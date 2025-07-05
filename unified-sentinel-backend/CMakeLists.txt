cmake_minimum_required(VERSION 3.15)
project(UnifiedSentinelBackend)

set(CMAKE_CXX_STANDARD 17)
add_definitions(-D_WIN32_WINNT=0x0601)

# Include paths (both Crow and local json.hpp)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(backend main.cpp)

# Find nlohmann_json package (if installed via package manager)
find_package(nlohmann_json CONFIG QUIET)

# Link only Windows sockets (json.hpp is header-only)
target_link_libraries(backend
    PRIVATE
        ws2_32    # Windows sockets
        wsock32   # Windows sockets
)

# Link nlohmann_json if found
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(backend PRIVATE nlohmann_json::nlohmann_json)
endif()