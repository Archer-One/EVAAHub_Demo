cmake_minimum_required(VERSION 3.24)
project(ClionProject)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)

if (PKG_CONFIG_FOUND)
    pkg_check_modules(my_deps REQUIRED IMPORTED_TARGET libbitcoin)
endif()
# gmp和pbc是必须要链接上去的


# 引入pbcwrapper的头文件和静态库
include_directories(${PROJECT_SOURCE_DIR}/pbcwrapper)
link_directories(${PROJECT_SOURCE_DIR}/pbcwrapper)

add_executable(ClionProject main.cpp Testing.cc global.h pairing_param.h DBSign.h DPKRS.h DZKRP.h tumbler.h sender.h payment_channel.h user.h struct_blind_payment.h)

target_link_libraries(${PROJECT_NAME} PkgConfig::my_deps)
target_link_libraries(${PROJECT_NAME} PBC)
target_link_libraries(${PROJECT_NAME} pbc gmp)
