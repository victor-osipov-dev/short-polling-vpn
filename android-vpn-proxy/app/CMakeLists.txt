cmake_minimum_required(VERSION 3.22.1)
project("vpnrunner")

add_library(vpnrunner SHARED
    src/main/cpp/vpn_runner.c
)

target_link_libraries(vpnrunner log)
